#!/bin/bash

VBoxManage guestcontrol $1 run --exe "/var/log/clean.sh" --username root --passwordfile mypassword.txt  --wait-stdout
