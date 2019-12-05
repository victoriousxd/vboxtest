#!/bin/bash

VM=$1

printf -v EXE "$2" 
echo "$EXE"
# create folder for executable
BASE="/home/carla/Desktop/mycpy/vboxtest/vBoxTest/audit/"
FOLDER="$BASE$EXE"
echo $FOLDER
mkdir $FOLDER
VBoxManage guestcontrol $VM copyfrom /var/log/audit/  $FOLDER --username root --passwordfile mypassword.txt
