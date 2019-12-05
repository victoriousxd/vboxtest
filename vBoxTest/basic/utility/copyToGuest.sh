#!/bin/bash

VM=$1
SRC=$2
ZIPFILENAME=$3

DEST="/home/"
echo $1
echo $SRC
echo $ZIPFILENAME
VBoxManage guestcontrol $VM copyto $SRC $DEST  --username root --passwordfile mypassword.txt
echo "copied"
VBoxManage --nologo guestcontrol $VM run --exe /home/clean.sh --username root --password meow \ --{$VM_EXEC}/arg0 $ZIPFILENAME 
echo "cleaned"
VBoxManage --nologo guestcontrol $VM run --exe /bin/ls --username root --password meow \ --{$VM_EXEC}/arg0 /home/badstuff >> fileList.txt



