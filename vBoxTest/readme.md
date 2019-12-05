## INITIAL SET UP
1. set home folder and master_vm in config file
2. install appliance on virtual box 

## LOAD FILES ON TO VM
1. Compress viruses into zip folder
2. Placed zip in bad_files folder from vbox.ini
3. run initialize.py with title of zip as argument
        this copies folders to vm
        then creates a list with all the file names

## GENERATE LOGS
1. run rawParse.py
    if configs are set up correctly... this is what happens:
    for every file in fileList.txt
        1. start vm
        2. execute collector for x seconds
            - runs executable 
            - generates logs in /var/log/audit
        3. copy logs to test_files directory
        4. parses logs for syscalls and combines them into a gzip file

## READ LOGS
demonstrated in readFile.py