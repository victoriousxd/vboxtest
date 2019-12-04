#!/bin/bash

#Run script with `./installPy.sh`, will install the pip install and necessary dependencies for the MLModule(classifier), GoAuditParser, consumer, & the API

##install python3.7-pip
sudo apt update
sudo apt install python3-pip --assume-yes

pip3 --version

##install modules for classifier with pip

pip3 install numpy --assume-yes
pip3 install sklearn --assume-yes

##install modules for consumer with pip

pip3 install pika --assume-yes

