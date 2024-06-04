#!/bin/bash

# Stop Docker containers
sudo docker stop $(sudo docker ps --format "{{.Names}}")

# Check if the bridge SWITCH already exists
bridge_exists=$(sudo ovs-vsctl get-bridge SWITCH)

# If the bridge exists, delete it
if [[ ! -z "$bridge_exists" ]]; then
  sudo ovs-vsctl del-br SWITCH
fi

# Create the bridge named SWITCH
sudo ovs-vsctl add-br SWITCH

# Bring the bridge interface up
sudo ifconfig SWITCH up

# Start the Docker containers
sudo docker start usuario slave1 slave2 slaver my_server

# Add bonded interfaces to the bridge with custom names
sudo ovs-docker add-port SWITCH eth0 usuario slave1 slave2 slave3 my_server
