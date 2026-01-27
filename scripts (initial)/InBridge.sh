#!/bin/bash

sudo pkill dhclient
sudo ip addr flush dev eth0
sudo ip route flush dev eth0
sudo ip link set eth0 master br0
sudo ip link set br0 up
sudo ip addr add 192.168.6.73/24 dev br0
sudo ip route add default via 192.168.6.254 dev br0
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo sysctl -w net.ipv6.conf.br0.proxy_ndp=1