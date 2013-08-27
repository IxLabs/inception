#!/bin/bash

source ./env

kill `cd $OVS/var/run/openvswitch && cat ovsdb-server.pid ovs-vswitchd.pid`


