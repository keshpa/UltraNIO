#!/usr/bin/bash
#
#!/bin/bash

# Check if the script is invoked with exactly one argument
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <network-interface>"
    exit 1
fi

# Argument passed to the script
INTERFACE="$1"

# Check if the argument is a valid network interface
if ip link show "$INTERFACE" > /dev/null 2>&1; then
    echo "Valid network interface: $INTERFACE"
else
    echo "Error: $INTERFACE is not a valid network interface."
    exit 2
fi

tc qdisc del dev $INTERFACE root
tc qdisc replace dev $INTERFACE root pfifo_fast
tc qdisc replace dev $INTERFACE root handle 1:0 htb default 30 r2q 50

# Queue 1: 80 Mbps
sudo tc class add dev $INTERFACE parent 1:0 classid 1:1 htb rate 80mbit ceil 80mbit

# Queue 2: 60 Mbps
sudo tc class add dev $INTERFACE parent 1:1 classid 1:10 htb rate 60mbit ceil 60mbit

# Queue 3: 30 Mbps
sudo tc class add dev $INTERFACE parent 1:1 classid 1:20 htb rate 30mbit ceil 30mbit

# Queue 4: 10 Mbps
sudo tc class add dev $INTERFACE parent 1:1 classid 1:30 htb rate 10mbit ceil 10mbit
