from glassboxAPI import *


fo = filterObject()
#fo.filterSyscall(8)
#fo.exeBlacklist = ["\"usr/bin/sudo\""]
#fo.PIDBlacklist = ["17418"]
#fo.IPBlacklist = ["172.17.0.1"]
#fo.IPWhitelist = ["172.17.0.2"]

strObj = StreamObject(fo)
while True:
	output = strObj.getDict()
	if(output!= None):
		print(output)
		strObj.closeStream()
		break
