import re
import os
import json
import sys 
import gzip

import configparser
from os import listdir
from os.path import isfile, join

# types represented by 1 byte
int10Types = [ 'syscall', 'ppid', 'pid', 'auid', 'uid', 'gid', 'euid', 'suid', 'fsuid', 'egid', 'sgid', 'fsgid', 'items']
# 64 bit byte strings
int16Types = [ "arch" ,"a0", "a1", "a2", "a3"]
floatTypes = ["timestamp"]
rx = re.compile("audit.(?P<timestamp>.*):(?P<sequence>.*).: arch=(?P<arch>.*) syscall=(?P<syscall>\d+) (?:success=(?P<success>.*) exit=(?P<exit>.*))?[ ]*a0=(?P<a0>.*) a1=(?P<a1>.*) a2=(?P<a2>.*) a3=(?P<a3>.*) items=(?P<items>.*) ppid=(?P<ppid>.*) pid=(?P<pid>.*) auid=(?P<auid>.*) uid=(?P<uid>.*) gid=(?P<gid>.*) euid=(?P<euid>.*) suid=(?P<suid>.*) fsuid=(?P<fsuid>.*) egid=(?P<egid>.*) sgid=(?P<sgid>.*) fsgid=(?P<fsgid>.*) tty=(?P<tty>.*) ses=(?P<ses>.*) comm=(?P<comm>.*) exe=(?P<exe>.*)[ ]*(?:subj=(?P<subj>.*))? key=(?P<key>.*)")
compressLvl = 4


sep ="/"
# set up from config file
name = ""
config = configparser.ConfigParser()
config.read('vbox.ini')

master_vm = config['userVar']['master_vm']
time = config['userVar']['time']    
cparams = config['linux']

if os.name == 'nt':
    cparams = config['windows']
    sep = "//"


home_dir = cparams['home_dir']
test_files = cparams['test_files']
bad_files = cparams['bad_files']







def appendLogs(directoryPath,finalName):
    logs, numLogs = appendLogFiles(directoryPath)
    finalOutput = gzip.open(finalName,"wb",compresslevel=compressLvl)
    for i in range(numLogs,0,-1):
        logName = directoryPath+sep+logs[i-1]
        print(logName)
        dataParseRaw(logName,finalOutput)
    finalOutput.close()

def dataParseRaw(filePath,finalOutput):
    f = open(filePath,"r")
    wtf = f.readlines()
    for line in wtf:
        if line[5:12] == "SYSCALL":
            result = re.search(rx,line)
            if result is not None:
                result = result.groupdict()
                for x in int10Types:
                    result[x] = int(result[x])

                for x in int16Types:
                    result[x] = int(result[x],16)
                
                if result['exit'] is not None:
                    result['exit'] = int(result['exit'])
                result['timestamp'] = float(result['timestamp'])
                j = json.dumps(result) + "\n"
                j = j.encode('utf-8')
                finalOutput.write(j)

                



def appendLogFiles(directoryPath):
    try:
        onlyfiles = [f for f in listdir(directoryPath) if isfile(join(directoryPath, f))]
        onlyfiles.sort()
        return onlyfiles, len(onlyfiles)
    except FileNotFoundError:
        print("Please use a valid executable name")
        sys.exit(1)