# vboxtest

Virtual Box Tester (VBT) is a tool that uses a preloaded virtual box image to record data on malware.

**How it works**
:	VBT is preloaded with a system auditor that can change kernel logging rules and audit specific programs.
	VBT can take a zipped file of executables and extract them into a virtual machine. 
Once the executables are loaded on the guest, it will run all of the executables through the collector. Each time the collector is run with a new executable, the virtual machine generates new audit logs for the host machine to collect. Once the logs are collected, the machine is reset to a clean snapshot and ready to run another executable. 

![VBox Diagram](./VBoxDiagram.jpg)

**Languages**
 :	Go, Bash, Python
 
 **Application**
 : VirtualBox, VBoxManage


***
###__PLEASE NOTE__
This is a beta version. Not tested on Windows. Needs to be monitored in case of hanging.
A sample virtual appliance (deb9.ova) can be found [here.](https://drive.google.com/open?id=1uBGywA5ym34UVLkAE4QpdcPiu8STqqsx)
root/password
 : meow/meow
 
### INITIAL SET UP
1. Install appliance on virtual box 
2. set **home folder and master_vm** in `/basic/vbox.ini`
3. Take a snapshot before loading.


#### vbox.ini sample file
```
***[linux/mac]***
home_dir = /home/carla/Desktop/mycpy/   # base folder of vboxtest
test_files = vboxtest/vBoxTest/audit    # where results go
bad_files = vboxtest/badstuff           # where compressed executables go
***[userVar]***
time = 5s                               # how long recording should take i.e. 1m is 1min
master_vm = deb9                        # name of the virtual machine you're using
```
### LOAD FILES ON TO VM

run ``./initialize Example_Viruses.zip``

1. Compress viruses into zip folder
2. Placed zip in **bad_files** folder from **vbox.ini**
3. Run `./initialize.py` with title of zip as argument
    * this copies folders to the guest virtual machine
    * then creates a list with all the file names in `vboxtest/vBoxTest/basic/utility/fileList.txt`
4. Take snapshot of clean virtual machine with loaded files

### GENERATE LOGS
run ``./rawParse.py``

If configs are set up correctly... this is what happens:
For every file in fileList.txt:

1. Starts the virtual machine
2. Execute `/home/collector` on guest machine for x seconds which :
    * runs executable  
    * enerates logs in `/var/log/audit`
    
3. copy logs to **test_files** directory.
4. parses logs for syscalls and combines them into a gzip file.



## READ LOGS
1. Open file as gzip
2. Read each line as JSON.
### Example

```python
#!/usr/bin/python3
import json
import gzip
path = "../vboxtest/vBoxTest/audit/VirusShare_000b031c08f518e06fc5fa7ffcf476d8.gzip"
f = gzip.open(path,'rb')
line = f.readline()
while line:
    stuff = json.loads(line)
    exe = stuff['exe']
    # do some stuff...
    if exe != "/usr/lib/erlang/erts-10.5.5/bin/beam.smp":
        print(exe)

```

### CLEAN UP
Restore the original snapshot of the virtual machine.
From there you can load files and run `./rawParse` again.

### SET UP GUEST MACHINE
1. Install Virtual Box Guest Additions.

2. Install Go, Python, and auditctl. Install script available for Linux users: `/vboxtext/install.sh`

2. Copy the collector binary (collectorSource) and config file (go-audit.yaml) into /home/ on the guest machine.

3. They are found in vBoxTest/collectorSource.

Update virtual macine root password with **mypassword.txt** in `vboxtest/vBoxTest/basic/utility/`

### KNOWN ISSUES

Reading logs can hang especially if the files are too large.
Consider changing the audit configuration log to reduce the file size or copying over a script to parse it before sending it back. 
Also considering working on using /bin/cat to read log files and parse them through standard out instead of copying log files and parsing them. 



***

### Acknowledgements
- Dr. Jim Purtilo - Professor/Advisor/Mentor
- Kevin Hogan - Client/Mentor


