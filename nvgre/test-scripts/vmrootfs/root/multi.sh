#!/bin/sh

count="$1"
id="$2"

count=$((count - 1))
for i in $(seq 0 $count); do
	./ip link add nv$i type nvgre vni $((10 + $i)) group 239.0.0.$((10 + $i)) ttl 10 dev eth0
	ip link set up dev nv$i
	ip a a 10.10.1.$id/24 dev nv$i
done
