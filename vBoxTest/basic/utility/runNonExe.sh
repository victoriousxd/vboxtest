#!/bin/bash
comm=/var/log/catlogs.py
echo comm
VBoxManage guestcontrol $1 run --exe $comm --username root --passwordfile mypassword.txt  --wait-stdout
