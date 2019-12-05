#!/usr/bin/python3
from helper import *
import subprocess
import sys
vmCount = 2
homebase = home_dir + bad_files

if len(sys.argv) == 1:
    print("Please provide executable in path ", homebase)
else:
    exe = sys.argv[1]
#load folder of executables from config
print("transferring folder {} to /home/badstuff".format(homebase))
comm = "./utility/copyToGuest.sh {} {} {}".format(master_vm,homebase,exe)
subprocess.run(comm, shell=True, check=True)
print("file list has been transferred to ./utility/fileList.txt")



