#!/bin/bash
# Убираем старые настройки
sudo ip addr flush dev eth0
sudo ip addr flush dev br0 2>/dev/null
sudo ip link set eth0 down
sudo ip link set br0 down 2>/dev/null
sudo ip link add name br0 type bridge

# Поднимаем физический интерфейс и добавляем в бридж
sudo ip link set eth0 up
sudo ip link set eth0 master br0

# Поднимаем бридж и назначаем IP
sudo ip link set br0 up
sudo ip addr add 192.168.6.38/24 dev br0


# Добавляем default route
sudo ip route replace default via 192.168.6.254 dev br0
