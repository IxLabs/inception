#!/bin/bash

# Create the database before the first time use

source ./env

ovsdb-tool create "$OVS/etc/openvswitch/conf.db" "$OVS_SRC/vswitchd/vswitch.ovsschema"
