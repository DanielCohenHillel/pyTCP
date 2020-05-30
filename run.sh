#!/bin/bash

sudo ip addr add 192.168.0.1/24 dev tun2
sudo ip link set up dev tun2
