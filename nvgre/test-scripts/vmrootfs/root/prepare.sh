#!/bin/sh

if [ -z "$1" ]; then
	host=$(hostname)
	if [ "$host" == "tn" -o "$host" == "1" ]; then
		id=1
	else
		id=2
	fi
else
	id="$1"
fi

./ip link add nv0 type nvgre vni 10 group 239.0.0.10 ttl 10 dev eth0
ip link set up dev nv0
ip a a 10.10.1."$id"/24 dev nv0


