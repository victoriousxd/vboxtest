#!/bin/bash
VBoxManage guestcontrol $1 run --exe "/home/cs/collectorSource" --username root --passwordfile mypassword.txt  --wait-stdout -- collectorSource -exe /home/exe/$2 -time $3

