#!/usr/bin/env python
import pika

connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
channel = connection.channel()

channel.queue_declare(queue='')

channel.basic_publish(exchange='syscalls',
                      routing_key='hello',
                      #body=r'{"sequence":5507536,"timestamp":"1572985433.142","messages":[{"type":1300,"data":"arch=c000003e syscall=44 success=yes exit=56 a0=3 a1=c000180000 a2=38 a3=0 items=0 ppid=2070 pid=3864 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm=\"go-audit\" exe=\"/root/Desktop/go-audit-master/go-audit\" subj==unconfined key=(null)"}],"uid_map":{"0":"root"}}')
                      body=r'{"interfaces":[{"iface":"lo","network_data":[{"ip":"127.0.0.1/8","mac":""},{"ip":"::1/128","mac":""}]},{"iface":"enp0s3","network_data":[{"ip":"10.0.2.15/24","mac":"08:00:27:3a:14:05"},{"ip":"fe80::cfc3:c550:4630:a320/64","mac":"08:00:27:3a:14:05"}]},{"iface":"docker0","network_data":[{"ip":"172.17.0.2/16","mac":"02:42:1d:04:c9:54"}]}],"sequence":"182244571","timestamp":"1574129170.148","arch":"c000003e","syscall":"8","success":"yes","exit":"0 ","a0":"4","a1":"0","a2":"1","a3":"0","items":"0","ppid":"20934","pid":"20936","auid":"1000","uid":"0","gid":"0","euid":"0","suid":"0","fsuid":"0","egid":"0","sgid":"0","fsgid":"0","tty":"pts3","ses":"3","comm":"\"sudo\"","exe":"\"/usr/bin/sudo\" subj==unconfined","subj":"","key":"(null)"}')
print(" [x] Sent 'Hello World!'")

connection.close()