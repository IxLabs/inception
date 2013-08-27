#!/bin/bash


# This script starts 2 virtual machines connected by an OVS bridge
# 
# Based on a script for VXLAN testing by Vincent Bernat
# https://github.com/vincentbernat/network-lab/tree/master/lab-vxlan


# Topology
#VM1                                   VM2
#eth0        - tap0  br0          tap2 - eth0
#10.0.0.1				 10.0.0.2

LABNAME="v6eval"
PROGNAME=$(readlink -f $0)
PROGARGS="$@"

ROOT=$(readlink -f ${ROOT:-/})
LINUX=$(readlink -f ${LINUX:-./linux})

WHICH=$(which which)
DEPS="screen brctl start-stop-daemon kvm cu socat perl"
CHROOTDEPS="ip"

# Filesystem hierarchy that will be selectively mounted (rw) in the VM
VMROOTFS="$PWD/vmrootfs"
# Root home directory
HOMESHARE="$VMROOTFS/root"

# Directory with installed kernel and modules
# It must contain the kernel image with the name $KERNEL_IMAGE_NAME
# and lib/modules/$kernel_version directory with modules
KERNEL_DIR="/home/alex/projects/net-next/build"
KERNEL_IMAGE_NAME="linux"

# OVS Installation prefix
OVS="/home/alex/projects/openvswitch/openvswitch-build/"

# The name of each VM
TN="ovs-1"
NUT="ovs-2"

# Bridge names. 
BR0="br0"

TAPS=""

info() {
    echo "[1;34m[+] $@[0m"
}

error() {
    echo "[1;31m[+] $@[0m"
}

# Setup a TMP directory
setup_tmp() {
    TMP=$(mktemp -d)
    trap "rm -rf $TMP" EXIT
    info "TMP is $TMP"
}

# Check for dependencies needed by this tool
check_dependencies() {
    for dep in $DEPS; do
        $WHICH $dep 2> /dev/null > /dev/null || {
            error "Missing dependency: $dep"
            exit 1
        }
    done
    [ -d $ROOT ] || {
        error "Chroot $ROOT does not exists"
    }
    for dep in $CHROOTDEPS; do
        PATH=$ROOT/usr/local/bin:$ROOT/usr/bin:$ROOT/bin:$ROOT/sbin:$ROOT/usr/local/sbin:$ROOT/usr/sbin \
            $WHICH $dep 2> /dev/null > /dev/null || {
            error "Missing dependency: $dep (in $ROOT)"
            exit 1
        }
    done
}

# Run our lab in screen
setup_screen() {
    [ x"$TERM" = x"screen" ] || \
        exec screen -ln -S $LABNAME -c /dev/null -t main "$PROGNAME" "$PROGARGS"
    sleep 1
    screen -X caption always "%{= wk}%-w%{= BW}%n %t%{-}%+w %-="
    screen -X zombie cr
}

# Generate  MAC address. Needs input seed
# $1   - input seed
# $mac - output MAC address
generate_mac() {
	mac=$(echo $1 | sha1sum | awk '{print "52:54:" substr($1,0,2) ":" substr($1, 2, 2) ":" substr($1, 4, 2) ":" substr($1, 6, 2)}')
}

# Start a VM
# $1 - VM name
start_vm() {
    info "Start VM $1"
    name="$1"
    shift

    case "$name" in
	"$TN")
	    POSTINIT="$TN_POSTINIT"
	    ;;
        "$NUT")
	    POSTINIT="$NUT_POSTINIT"
	    ;;
    esac

    netargs=""
    for net in $NET; do
	generate_mac "$name-$net-$IFACE"
	if [ "$name" == "$NUT" ]; then
		mac="00:00:cc:dd:ee:ff"
	fi
	netargs="-net nic,macaddr=$mac -net tap,script=$PWD/ovs-ifup,downscript=$PWD/ovs-ifdown"
	netargs="-device e1000,netdev=net0,mac=$mac -netdev tap,id=net0,script=$PWD/ovs-ifup,downscript=$PWD/ovs-ifdown"

	generate_mac "$name-$net-$IFACE"
	if [ "$name" == "$NUT" ]; then
		mac="00:01:cc:dd:ee:ff"
	fi
	netargs="-net nic,macaddr=$mac -net tap,script=$PWD/ovs-ifup,downscript=./ovs-ifdown"
	netargs="-device e1000,netdev=net0,mac=$mac -netdev tap,id=net0,script=$PWD/ovs-ifup,downscript=$PWD/ovs-ifdown"
    done

    # /root is mounted with version 9p2000.u to allow access to /dev,
    # /sys and to mount new partitions over them. This is not the case
    # for 9p2000.L.
    screen -t $name -c screenrc \
        start-stop-daemon --make-pidfile --pidfile "$TMP/vm-$name.pid" \
        --start --startas $($WHICH kvm) -- \
        -nodefconfig -no-user-config -nodefaults \
        -m 256m \
        -display none \
        \
        -chardev stdio,id=charserial0,signal=off \
        -device isa-serial,chardev=charserial0,id=serial0 \
        -chardev socket,id=charserial1,path=$TMP/vm-$name-serial.pipe,server,nowait \
        -device isa-serial,chardev=charserial1,id=serial1 \
        \
        -chardev socket,id=con0,path=$TMP/vm-$name-console.pipe,server,nowait \
        -mon chardev=con0,mode=readline,default \
        \
        -fsdev local,security_model=passthrough,id=fsdev-root,path=${ROOT},readonly \
        -device virtio-9p-pci,id=fs-root,fsdev=fsdev-root,mount_tag=/dev/root \
        -fsdev local,security_model=none,id=fsdev-home,path=${VMROOTFS} \
        -device virtio-9p-pci,id=fs-home,fsdev=fsdev-home,mount_tag=overlayshare \
        -fsdev local,security_model=none,id=fsdev-lab,path=${KERNEL_DIR} \
        -device virtio-9p-pci,id=fs-lab,fsdev=fsdev-lab,mount_tag=kernelshare \
        \
        -gdb unix:$TMP/vm-$name-gdb.pipe,server,nowait \
        -kernel "${KERNEL_DIR}/${KERNEL_IMAGE_NAME}" \
        -append "init=$PROGNAME console=ttyS0 uts=$name root=/dev/root rootflags=trans=virtio,version=9p2000.u ro rootfstype=9p POSTINIT=\"$POSTINIT\"" \
        $netargs \
        "$@"
    echo "GDB server listening on.... $TMP/vm-$name-gdb.pipe"
    echo "monitor listening on....... $TMP/vm-$name-console.pipe"
    echo "ttyS1 listening on......... $TMP/vm-$name-serial.pipe"

    screen -X select 0
}

display_help() {
    cat <<EOF

Some screen commands :
 C-a d     - Detach the screen (resume with screen -r $LABNAME)
 C-a "     - Select a window
 C-a space - Next window
 C-a C-a   - Previous window
EOF
    echo "Press enter to exit the lab"

    read a
}

setup_ovs() {

	ovsdb-server --remote=punix:$OVS/var/run/openvswitch/db.sock \
                     --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
                     --private-key=db:Open_vSwitch,SSL,private_key \
                     --certificate=db:Open_vSwitch,SSL,certificate \
                     --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
                     --pidfile --detach

	ovs-vsctl --no-wait init

	ovs-vswitchd --pidfile --detach
}

setup_bridges() {
    ovs-vsctl add-br $BR0

    # Use external controller
    #ovs-vsctl set-controller $BR0 tcp:0.0.0.0:6633

    # Give access to the outside network
    #ovs-vsctl add-port $BR0 eth0
}

cleanup() {
    for pid in $TMP/*.pid; do
        kill -15 -$(cat $pid) 2> /dev/null || true
    done
    sleep 1
    for pid in $TMP/*.pid; do
        kill -9 -$(cat $pid) 2> /dev/null || true
    done

    ip link set down dev $BR0

    ovs-vsctl del-br $BR0

    kill `cd $OVS/var/run/openvswitch && cat ovsdb-server.pid ovs-vswitchd.pid`


    rm -rf $TMP # sh does not seem to handle "trap EXIT"
    screen -X quit
}

export STATE=${STATE:-0}
case $$,$STATE in
    1,0)
        # Initrd
        info "Setup hostname"
        hostname ${uts}
        info "Set path"
        export TERM=screen
        export HOME=/root
        export PATH=/usr/local/bin:/usr/bin:/bin:/sbin:/usr/local/sbin:/usr/sbin:$HOME/bin

        info "Setup overlayfs"
        mount -t tmpfs tmpfs /tmp -o rw
        mount -n -t proc  proc /proc
        mount -n -t sysfs sys /sys

	mkdir /tmp/vmroot
        mount -t 9p overlayshare /tmp/vmroot -o trans=virtio,version=9p2000.L,access=0,rw

        info "Mount home directory on /root"
	mount -o bind /tmp/vmroot/root /root

	info "Mount /etc"
	mount -o bind /tmp/vmroot/etc/ /etc

	info "Mount kernel modules"
	mkdir /tmp/kernel
	mount -t 9p kernelshare /tmp/kernel -o trans=virtio,version=9p2000.L,access=0,rw
	mount -o bind /tmp/kernel/lib/modules /lib/modules

        # In chroot
        info "Clean out /tmp and /run directories"
        for fs in /run /var/run /var/tmp /var/log; do
            mount -t tmpfs tmpfs $fs -o rw,nosuid,nodev
        done

        info "Setup interfaces"
        for intf in /sys/class/net/*; do
            intf=$(basename $intf)
            ip a l dev $intf 2> /dev/null >/dev/null || continue
            case $intf in
                lo|eth*|dummy*)
                    ip link set up dev $intf
                    ;;
            esac
        done

	# Need devpts for remote logins
	mkdir -p /dev/pts
	mount -t devpts none /dev/pts
	
        info "Setup terminal"
        export STATE=2
        exec setsid /sbin/agetty -L ttyS0 -a root -l "$PROGNAME" -i 115200
        ;;
    1,2)
        export TERM=screen

        info "Lab specific setup"
        export STATE=3
	. "/etc/rc.local"
        . "$PROGNAME"
	
	if [ "$POSTINIT" ]; then
		info "Running postinit: $POSTINIT"
		"$POSTINIT"
	fi
	
        while true; do
            info "Spawning a shell"
            cd $HOME
            export SSH_TTY=$(tty)
            if [ -f $HOME/.zshrc ]; then
                /bin/zsh -i
            else
                /bin/bash -i
            fi || sleep 1
        done
        ;;
    *,3)
        # Specific setup for this lab
        info "Enable forwarding"
        sysctl -w net.ipv4.ip_forward=1

	info "Enable SLIP"
	modprobe slip

	mount -t debugfs none /sys/kernel/debug
        ;;
    *,*)
        [ $(id -u) != 0 ] || {
            error "You should not run this as root, unless you use tap devices"
            #exit 1
        }
	source ./env

        check_dependencies
        setup_screen
        setup_tmp

	setup_ovs
	setup_bridges

	mkdir -p "$HOMESHARE/bin"


        sleep 0.3
        NET=1 VLAN=0 start_vm $TN
        NET=2 VLAN=0 start_vm $NUT

	# Create a serial line between the 2 VMs
	sleep 2
	socat "$TMP/vm-$TN-serial.pipe" "$TMP/vm-$NUT-serial.pipe" &

        display_help
        cleanup

	killall socat

        ;;
esac

# Local Variables:
# mode: sh
# indent-tabs-mode: nil
# sh-basic-offset: 4
# End:
