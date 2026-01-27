#!/bin/bash

sudo pkill dhclient

sudo ip addr flush dev eth0

sudo ip link set br0 up

sudo ip addr flush dev br0
sudo ip addr add 192.168.6.73/24 dev br0

sleep 1

ping -c 2 192.168.6.254
if [ $? -ne 0 ]; then
  echo "Шлюз недоступен! Проверьте сеть/кабель/роутер."
  exit 1
fi

sudo ip route flush default
sudo ip route add default via 192.168.6.254 dev br0

sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo sysctl -w net.ipv6.conf.all.proxy_ndp=1
sudo sysctl -w net.ipv6.conf.br0.proxy_ndp=1
