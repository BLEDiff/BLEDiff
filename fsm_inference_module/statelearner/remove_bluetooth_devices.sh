#!/bin/bash 
for device in $(bt-device -l | grep -o "[[:xdigit:]:]\{11,17\}"); do
    echo "removing bluetooth device: $device | $(bt-device -r $device)"
done