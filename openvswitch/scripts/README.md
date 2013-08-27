
Open vSwitch scripts for testing purposes
---

FILES
=====

run.sh:
- start 2 KVM virtual machines that use openvswitch as a bridge
- the actual setup is done by build-lab.sh
- build-lab.sh also starts/stops the openvswitch daemons
- need to insmod openvswitch and tun before running
- must be run as root

ovs-if{up,down}:
- helper scripts for qemu
- automatically creates a tun device and adds it to the bridge

env:
- exports OVS, OVS_SRC and PATH for using openvswitch commands
- uptdate them with your own paths
- OVS: installation prefix for openvswitch
- OVS_SRC: source directory

create-db.sh:
- creates the openvswitch database

{start,stop}-server.sh:
- runs/stops the openvswitch daemons
- must be run as root

BASIC USAGE
===========

- build openvswitch and install
- update 'env' with the actual paths
- insmod tun (if used) and openvswitch (from $OVS_SRC/datapath/linux/openvswitch.ko)
- ./create-db.sh
- sudo ./start-server.sh
- control openvswitch with 'ovs-' commands
- sudo ./stop-server.sh

- logs are in $OVS/var/log/openvswitch

KVM
===

- insmod tun and openvswitch
- sudo ./run.sh

