#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root kapara"
  exit
fi
# ip addr add 192.168.0.1/24 dev tun2
# ip link set up dev tun2
./tcpimp.py -s
