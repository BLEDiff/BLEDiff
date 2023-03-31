#!/bin/bash
sudo hciconfig hci0 down
sudo btmgmt le on
sudo btmgmt bredr off
sudo hciconfig hci0 up
#sleep 1

