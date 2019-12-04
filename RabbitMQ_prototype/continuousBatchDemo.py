from glassboxAPI import *


#fo = filterObject()
#fo.filterSyscall(8)
#fo.blacklistComm("\"sudo\"")
#fo.blacklistPID("17418")
#fo.blacklistIP("172.17.0.1")

def sampleCallback(d):
	print(d)

getContinuousBatches(5,sampleCallback,True)
while True:
	print("This is proof I'm not blocking!")
	time.sleep(3)