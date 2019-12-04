In order to use this you must install RabbitMQ and start it on localhost

as well as installing python-strace and pika

python3 -m install python-strace
python3 -m install pika


The motivation behind using a messaging queue is to allow multiple researchers to tap into the same live feed of syscalls. You can have multiple consumers doing different tasks with this data, all they need to do is to properly connect to the RabbitMQ server and subscribe to the stream. 


To test this run consumer.py (or multiple :]) and then run strace.py [path to executable]

you will see all consumers get the same syscall data
