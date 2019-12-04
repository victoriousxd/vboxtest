    #!/bin/bash
     
    echo $0
     
    full_path=$(realpath $0)
    echo $full_path
     
    dir_path=$(dirname $full_path)
    echo $dir_path
     
    examples=$(dirname $dir_path )
    echo $examples
     
    data_dir="$examples/data"
    echo "DATA: $data_dir"
     
     
     
VM=$1
FILES=$2

# file to copy 
PATH =  "/home/carla/Desktop/mycpy/vboxtest/badstuff" + $2 

VBoxManage guestcontrol $VM copyfrom "/var/log/audit" $PATH --username root --passwordfile mypassword.txt
