#!/usr/bin/python3
import json
import gzip
path = "./audit/VirusShare_000b031c08f518e06fc5fa7ffcf476d8.gzip"
f = gzip.open(path,'rb')
line = f.readline()
while line:
    stuff = json.loads(line)
    exe = stuff['exe']
    # do some stuff...
    if exe != "/usr/lib/erlang/erts-10.5.5/bin/beam.smp":
        print(exe)
