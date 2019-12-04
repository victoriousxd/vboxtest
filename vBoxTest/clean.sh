#!/bin/bash



mysnaps=$(VBoxManage snapshot cmsc433-vm list)
ECHO $mysnaps
IFS=':' read -a ARR <<< $mysnaps


for i in "${ARR[@]}"; do
    echo "----"
    echo $i
done

declare -p ARR