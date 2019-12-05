#!/usr/bin/python3
from helper import *
import subprocess
from os import listdir
from os.path import isfile, join


virusList = open('utility/fileList.txt',"r").readlines()
for x in virusList:
    name = x.strip()
    test_file_directory = home_dir+test_files+sep+name
    finalName ="{}.gzip".format(test_file_directory)
    print("converting directory {} to file {}".format(test_file_directory,finalName))
    comm = "./execute.sh {} {} {}".format(master_vm,name,time)
    
    try:
        subprocess.run(comm, shell=True, check=True)
    except:
        ""
       
    
    appendLogs(test_file_directory,finalName)
    

    subprocess.run("rm -r /home/carla/Desktop/mycpy/vboxtest/vBoxTest/audit/{}".format(name), shell=True, check=True)

