import socket
import sys
import os
import select
import struct
import signal
from threading import Timer
from threading import Thread
import time
import json




server_address = '/tmp/GLASSBOX_API_SOCKET'

class filterObject:
	def __init__(self):
		#Bitfields are stored by performing bitwise operations on ints using powers of 2
		#bitfield is seperated into many ints to keep size consistent
		self.bitfields = {
			32:0,
			64:0,
			96:0,
			128:0,
			160:0,
			192:0,
			224:0,
			256:0,
			288:0,
			320:0,
			352:0,
			384:0,
			416:0,
			448:0
		}
		self.exeBlacklist = []
		self.PIDBlacklist = []
		self.IPBlacklist = []
		self.exeWhitelist=[]
		self.PIDWhitelist=[]
		self.IPWhitelist=[]

	def filterSyscall(self, syscallNum):
		for k in self.bitfields:
			if syscallNum < k:
				self.bitfields[k] = self.bitfields[k] | (2**(syscallNum-1-k+32))
				break

	def unfilterSyscall(self, syscallNum):
		for k in self.bitfields:
			if syscallNum < k:
				self.bitfields[k] = self.bitfields[k] & (~(2**(syscallNum-1-k+32)))
				break

	def isSyscallFiltered(self, syscallNum):
		bitfieldLength = 0xffff
		for k in self.bitfields:
			if syscallNum < k:
				if ((self.bitfields[k] & (2**(syscallNum-1-k+32))) & bitfieldLength != 0):
					return True
				else:
					return False

class StreamObject:
	def __init__(self, filters=None):
		# Create a UDS socket
		self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		# Connect the socket to the port where the server is listening
		print ('connecting')
		try:
			self.sock.connect(server_address)
		except socket.error as e:
			print(e)
		
		#Send initial message
		if (filters==None):
			message = 's'
			print ('sending ' + message)
			self.sock.sendall(message.encode('utf-8'))
		else:
			message = 'S'
			print ('sending ' + message)
			self.sock.sendall(message.encode('utf-8'))
			sendBitfield(filters.bitfields, self.sock)
			sendList(filters.exeBlacklist, self.sock)
			sendList(filters.PIDBlacklist, self.sock)
			sendList(filters.IPBlacklist, self.sock)
			sendList(filters.exeWhitelist, self.sock)
			sendList(filters.PIDWhitelist, self.sock)
			sendList(filters.IPWhitelist, self.sock)

	def getDict(self):
		#Returns the next dict from the socket, or None if there is none
		res = select.select([self.sock],[],[],0)
		if (len(res[0])>0): 
			dataLen = self.sock.recv(4)
			dataLen = int.from_bytes(dataLen,byteorder='little')
			data = self.sock.recv(dataLen)
			data = data.decode("utf-8")
			return stringToDict(data)
		else:
			return None

	def getRawSocket(self):
		return self.sock

	def closeStream(self):
		self.sock.close()

def getContinuousBatches(size, callback, seperateThread=True, filters=None):
	#Takes a size for the batch to be output,
	#a callback, which will recieve data in the form of a list of dicts,
	#a seperateThead value, which if true will run the stream and callback in the background,
	#and filters

	#Returns a thread if seperateThread is true
	if(seperateThread == False):
		stream = StreamObject(filters)
		batch = []
		while True:
			data = stream.getDict()
			if(data!= None):
				batch.append(data)
				if(len(batch) == size):
					callback (batch)
					batch = []
	else:
		t = Thread(target=getContinuousBatches, args=(size,callback,False,filters))
		t.start()
		return t


def getUniqueContBatches(size, callback, seperateThread=True, filters=None):
	# Takes a size for the batches and  a callback. This callback will receive the data in the form
	# of a list of dicts. A seperateThread value, which if true will run the stream and callback in
	# the background.

	if seperateThread is False:
		stream = StreamObject(filters)
		batches = {}
		while True:
			data = stream.getDict()
			if data != None:
				exe = data["exe"]
				if exe in batches:
					batches[exe].append(data)
					if len(batches[exe]) == size:
						callback(batches[exe])
						batches[exe] = []
				else:
					batches[exe] = [data]
	else:
		t = Thread(target=getUniqueContBatches, args=(size,callback,False,filters))
		t.start()
		return t

def getBatchByTime(timeAmount, callback, filters=None):
	#Takes a timeAmount in seconds to collect up calls,
	#a callback, which will recieve data in the form of a list of dicts,
	#and filters
	sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	print ('connecting')
	try:
		sock.connect(server_address)
	except socket.error as e:
		print(e)
	try:
		#send the consumer the request
		if (filters==None):
			message = 't'
			sock.sendall(message.encode('utf-8'))
			sock.sendall(struct.pack('i', timeAmount))
		else:
			message = 'T'
			sock.sendall(message.encode('utf-8'))
			sock.sendall(struct.pack('i', timeAmount))
			sendBitfield(filters.bitfields,sock)
			sendList(filters.exeBlacklist, self.sock)
			sendList(filters.PIDBlacklist, self.sock)
			sendList(filters.IPBlacklist, self.sock)
			sendList(filters.exeWhitelist, self.sock)
			sendList(filters.PIDWhitelist, self.sock)
			sendList(filters.IPWhitelist, self.sock)
	except:
		print("Failure in initial communication")
		return None
	#Sets a timer for the second phase of the function- recieving the data
	t = Timer(timeAmount, getBatchByTime2, [sock, callback])
	t.start()
	return t

def getBatchByTime2(sock, callback):
	#Meant only to be called by getBatchByTime
	toSendToCallback = []
	while(len(select.select([sock],[],[],0)[0]) > 0):#While there is data to recv
		dataLen = sock.recv(4)
		dataLen = int.from_bytes(dataLen,byteorder='little')
		data = sock.recv(dataLen)
		data = data.decode('utf-8')
		d = stringToDict(data)
		toSendToCallback.append(d)
	sock.close()
	callback(toSendToCallback)

def getBatchBySize(num):
	#Does not work with filtering, recomend use of getContinuousBatches 
	#unless performance is really an issue and no filtering plus randomness are acceptable tradoffs
	toReturn=[]
	# Create a UDS socket
	sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	# Connect the socket to the port where the server is listening
	print ('connecting')
	try:
		sock.connect(server_address)
	except socket.error as e:
		print(e)
	try:
		# Send initial message
		message = 'b'
		sock.sendall(message.encode('utf-8'))
		sock.sendall(struct.pack('i', num))
	except:
		print("Failure in initial communication")
		return None
	accept = sock.recv(1)
	print(accept)
	if(accept==b'y'):
		for x in range(0,num):
			dataLen = sock.recv(4)
			dataLen = int.from_bytes(dataLen,byteorder='little')
			data = sock.recv(dataLen)
			data = data.decode('utf-8')
			d = stringToDict(data)
			toReturn.append(d)
		sock.close()
		return toReturn

	else:
		print("Consumer rejected the request. Ensure that you are not asking for a larger batch than the consumer's history size allows.")
		return None
	
#Utility Functions
def sendList(listToSend, sock):
	#Sends a list of strings across socket in format consumer can understand
	numItems = len(listToSend)
	message=struct.pack('i', numItems)
	sock.sendall(message)
	for item in listToSend:
		lenItem = len(item)
		message=struct.pack('i', lenItem)
		sock.sendall(message)
		sock.sendall(item.encode('utf-8'))


def sendBitfield(bitfields, sock):
	#Sends the bitfield chuncks across socket in format consumer can understand
	for k in bitfields:
		message=struct.pack('I', bitfields[k])
		sock.sendall(message)

def stringToDict(text):
	return json.loads(text)




