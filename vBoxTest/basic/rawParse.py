#!/usr/bin/python3

import configparser


from helper import *
batchSize = 64 # size of each batch



# set up from config file
config = configparser.ConfigParser()
config.read('vbox.ini')

home_dir = config['paths']['home_dir']
master_vm = config['paths']['master_vm']
test_files = config['paths']['test_files']
time = config['paths']['time']

name ="lol.py"

test_file_directory = home_dir+test_files+sep+name


finalName = home_dir+test_files+sep+name+".gzip"


appendLogs(test_file_directory,finalName)




