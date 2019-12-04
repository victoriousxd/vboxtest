#!/bin/bash
comm=/bin/$2
echo comm
VBoxManage guestcontrol $1 run --exe $comm --username root --passwordfile mypassword.txt  --wait-stdout -- ls /home/exe -- $2 $3


