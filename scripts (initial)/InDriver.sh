#!/bin/bash
sudo modprobe usbserial 
sudo modprobe ftdi_sio
echo "0403 a6d1" | sudo tee /sys/bus/usb-serial/drivers/ftdi_sio/new_id
