#!/usr/bin/python3
import subprocess
import sys
from os import listdir
from os.path import isfile, join

def appendLogFiles(directoryPath):
    try:
        onlyfiles = [f for f in listdir(directoryPath) if isfile(join(directoryPath, f))]
        onlyfiles.sort()
        return onlyfiles, len(onlyfiles)
    except FileNotFoundError:
        print("Please use a valid executable name")
        sys.exit(1)

path = '/var/log/'
logs, numLogs = appendLogFiles(path)
print(logs)

for i in range(numLogs,0,-1):
    comm = "/bin/ls {}".format(path+i)
    subprocess.run(comm, shell=True, check=True)