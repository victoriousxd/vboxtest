#!/bin/bash

VBoxManage --nologo guestcontrol $1 run --exe /home/$1 --username root --password meow \ --{$VM_EXEC}/arg0 $2 

