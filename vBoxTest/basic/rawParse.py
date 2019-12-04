#!/usr/bin/python3
import re
from os import listdir
from os.path import isfile, join
import json
batchSize = 64 # size of each batch



# types represented by 1 byte
byteTypes = ["success"]
int10Types = ["exit","syscall", "Ppid", "Pid", "Auid", "Uid", "Gid", "Euid", "Suid", "Fsuid", "Egid", "Sgid", "Fsgid","Items"]
# 64 bit byte strings
int16Types = [ "arch" ,"a0", "a1", "a2", "a3"]
floatTypes = ["timestamp"]
emptyValues = ["", "(none)"]
rx = re.compile("audit.(?P<timestamp>.*):(?P<sequence>.*).: arch=(?P<arch>.*) syscall=(?P<syscall>\d+) (?:success=(?P<success>.*) exit=(?P<exit>.*))?[ ]*a0=(?P<a0>.*) a1=(?P<a1>.*) a2=(?P<a2>.*) a3=(?P<a3>.*) items=(?P<items>.*) ppid=(?P<ppid>.*) pid=(?P<pid>.*) auid=(?P<auid>.*) uid=(?P<uid>.*) gid=(?P<gid>.*) euid=(?P<euid>.*) suid=(?P<suid>.*) fsuid=(?P<fsuid>.*) egid=(?P<egid>.*) sgid=(?P<sgid>.*) fsgid=(?P<fsgid>.*) tty=(?P<tty>.*) ses=(?P<ses>.*) comm=(?P<comm>.*) exe=(?P<exe>.*)[ ]*(?:subj=(?P<subj>.*))? key=(?P<key>.*)")

name= "lol.py"
PATH = "/home/carla/Desktop/mycpy/vboxtest/vBoxTest/audit/"+name+"/"
finalName = PATH+ name + ".log"
finalOutput = open(finalName,"w+")
print(finalName)

def dataParseRaw(path):
    f = open(path,"r")
    wtf = f.readlines()

    for line in wtf:
        if line[5:12] == "SYSCALL":
            result = re.search(rx,line)
            if result is not None:
                result = result.groupdict()
                for x in int10Types:
                    if x is not None:
                        x = x.lower()
                        print(result[x])
                        result[x] = int(result[x])
                for x in int16Types:
                    result[x] = int(result[x],16)
                result['timestamp'] = float(result['timestamp'])
                j = json.dumps(result)
                finalOutput.write(j)
                finalOutput.write("\n")



def appendExeFiles(mypath):
    onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]
    onlyfiles.sort()
    return onlyfiles, len(onlyfiles)



logs, numLogs = appendExeFiles(PATH)
for i in range(numLogs,0,-1):
    print(logs[i-1])
    dataParseRaw(PATH+logs[i-1])


