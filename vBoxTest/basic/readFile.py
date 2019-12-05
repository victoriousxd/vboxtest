#!/usr/bin/python3
import json
import gzip
path = "/home/carla/Desktop/mycpy/vboxtest/vBoxTest/audit/VirusShare_000b031c08f518e06fc5fa7ffcf476d8.gzip"

allFields = ["sequence","timestamp","arch", "syscall", "success", "exit", "a0", "a1", "a2", "a3", "items", "ppid", "pid", "auid", "uid", "gid", "euid", "suid", "fsuid", "egid", "sgid", "fsgid", "tty", "ses", "comm", "exe", "subj", "key"]

batchSize = 100
def processFile(fpath_, wants):
    lineNumber = 0
    batches = []
    f = gzip.open(path,'rb').readlines()
    batch = []

    for line in f:
        line = json.loads(line)

        data = dataParseFile(line, wants)
        if len(data) != len(wants):
            # TODO: exit or skip improperly formatted data?
            print("Missing property found at {}:\n{}", lineNumber, line)
            #exit(-1)  # shouldn't read corrupt data, exit
        else:
            lineNumber += 1
            batch.append(data)
            if lineNumber % batchSize == 0:
                batches.append(batch)
                print(batch)
                batch = []
                
                

    if len(batch) > 0:
        batches.append(batch)
    
    return batches



def dataParseFile( line, wants):
    # make sure data is properly formatted
    output = {key: None for key in wants}
    for x in line.keys():
        if x in wants:
            output[x] = line[x]


    return list(output.values())

processFile(path,allFields)