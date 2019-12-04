#!/usr/bin/python3
import pika
import socket
import sys
import os
import struct
from threading import Thread
from queue import Queue
import select
import time
import json
import binascii

q = Queue()

def testFilters(newItemDict, exeBlacklist, PIDBlacklist, IPBlacklist, exeWhitelist, PIDWhitelist, IPWhitelist):
	sendData = True
	if(len(exeWhitelist)>0):
		sendData = False
		for exe in exeWhitelist:
			if(exe==newItemDict["exe"]):
				sendData = True

	if(len(PIDWhitelist)>0):
		sendData = False
		for PID in PIDWhitelist:
			if(PID==newItemDict["pid"]):
				sendData = True
				
	if(len(IPWhitelist)>0):
		sendData = False
		for IP in IPWhitelist:
			for interface in newItemDict["interfaces"]:
				interfaceData = interface["network_data"]
				for ipmac in interfaceData:
					ip = ipmac["ip"]
					if (IP == ip or IP == ip.split('/')[0]):
						sendData = True

	for exe in exeBlacklist:
		if(exe==newItemDict["exe"]):
			sendData=False
			break
	if(sendData):
		for PID in PIDBlacklist:
			if(PID==newItemDict["pid"]):
				sendData=False
				break
		if(sendData):
			for blIP in IPBlacklist:
				for interface in newItemDict["interfaces"]:
					interfaceData = interface["network_data"]
					for ipmac in interfaceData:
						ip = ipmac["ip"]
						if (blIP == ip or blIP == ip.split('/')[0]):
							sendData=False
							break
	return sendData

def recoverBitfield(connection):
	bitfields={
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
	for k in bitfields:
		bitfield=connection.recv(4)
		bitfield=int.from_bytes(bitfield,byteorder='little',signed=False)
		bitfields[k] = bitfield
	return bitfields

def recoverList(connection):
	toReturn = []
	numItems = connection.recv(4)
	numItems=int.from_bytes(numItems,byteorder='little')
	for x in range(0,numItems):
		strLen = connection.recv(4)
		strLen = int.from_bytes(strLen,byteorder='little')
		toReturn.append(connection.recv(strLen).decode('utf-8'))
	return toReturn


def contains(bitfields, syscallNum):
	bitfieldLength = 0xffff
	for k in bitfields:
		if syscallNum < k:
			if ((bitfields[k] & (2**(syscallNum-1-k+32))) & bitfieldLength != 0):
				return True
			else:
				return False

def main():
	try:
		size = int(sys.argv[1])
		historySize = size
	except:
		historySize=1
		

	t1 = Thread(target=threadActivity,args=([historySize]))
	t1.start()
	#-------------------------------------------------------------
	#credentials = pika.PlainCredentials('admin','password')
	credentials = pika.PlainCredentials('admin','password')
#'volatility.cs.umd.edu'
	connection = pika.BlockingConnection(
		pika.ConnectionParameters('volatility.cs.umd.edu',5672,'/',credentials))
	channel = connection.channel()

	channel.exchange_declare(exchange='syscalls', exchange_type='fanout')

	result = channel.queue_declare(queue='', exclusive=True)
	queue_name = result.method.queue

	channel.queue_bind(exchange='syscalls', queue=queue_name)

	print(' [*] Waiting for syscalls. To exit press CTRL+C')

	channel.basic_consume(
	    queue=queue_name, on_message_callback=callback, auto_ack=True)

	channel.start_consuming()

	#----------------------------------------------------
def readString(b,i):

  length = unpack("h",b[i:i+2])[0]
  result = (b[i+2:length+i+2])

  if length == 0:
    result = ""

  return result,length+2
  

def callback(ch, method, properties, body):
	for i in body:
		print(hex(i)[2:].zfill(2))
	index = 0
	for i in range(6):
		s, length = readString(body,index)
		index += length


	q.put(json.dumps(body))


def threadActivity(historySize):
	history = []
	server_address = '/tmp/GLASSBOX_API_SOCKET'
	# Make sure the socket does not already exist
	try:
		os.unlink(server_address)
	except OSError:
		if os.path.exists(server_address):
			raise

	# Create a UDS socket
	sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

	# Bind the socket to the address
	sock.bind(server_address)

	# Listen for incoming connections
	sock.listen(1)
	#----------
	streamRequests = []
	timedRequests = []
	while True:
		# Check for a connection, and accept
		acceptNewConnections(sock, streamRequests, timedRequests, history)
		
		#Poll the Queue. If it doesnt have anything new, check for new connections again
		try:
			newItem = q.get(block=False)
			print(newItem)
		except:
			continue

		#Get the newest syscall as a dictionary for filtering
		
		#newItemDict = newItem

		#Add to history, keep history at historySize
		history.append(newItem)
		if(len(history)>historySize):
			history.pop(0)
			
		#Create a list of closed connections to be removed from our list of connections
		srToRemove = []

		#Loop through our connection tuples to potentially send data
		for conTup in streamRequests:
			con = conTup[0]
			bitfield = conTup[1]
			exeBlacklist = conTup[2]
			PIDBlacklist = conTup[3]
			IPBlacklist = conTup[4]
			exeWhitelist = conTup[5]
			PIDWhitelist = conTup[6]
			IPWhitelist = conTup[7]

			#If the other side closes the connection, add it the list to close
			if(len(select.select([con],[],[],0)[0]) > 0):
				print("Closing connection")
				con.close()
				srToRemove.append(conTup)			
			else:
				#If the bitfield associated with the connection is None, or doesn't block this one
				if (bitfield == None or contains(bitfield, int(newItemDict["syscall"])) == False):
					#Check all the other conditions
					sendData = testFilters(newItemDict, exeBlacklist, PIDBlacklist, IPBlacklist, exeWhitelist, PIDWhitelist, IPWhitelist)
					if(sendData):
						#If the data hasn't matched any filters, send it
						b = struct.pack('i',len(newItem))
						con.sendall(b)
						con.sendall(newItem)
		#Remove all the connections noted to be closed
		for c in srToRemove:
			streamRequests.remove(c)

		#Do the same for timed requests, except check for time as part of the process
		trToRemove = []
		for conTup in timedRequests:
			con = conTup[0]
			expiration = conTup[1]
			bitfield = conTup[2]
			exeBlacklist = conTup[3]
			PIDBlacklist = conTup[4]
			IPBlacklist = conTup[5]
			exeWhitelist = conTup[6]
			PIDWhitelist = conTup[7]
			IPWhitelist = conTup[8]
			if (time.time() > expiration):
				trToRemove.append(conTup)
			else:
				if (bitfield == None or contains(bitfield, int(newItemDict["syscall"])) == False):
					sendData = testFilters(newItemDict, exeBlacklist, PIDBlacklist, IPBlacklist, exeWhitelist, PIDWhitelist, IPWhitelist)
					if(sendData):
						b = struct.pack('i',len(newItem))
						con.sendall(b)
						con.sendall(newItem)
		for c in trToRemove:
			timedRequests.remove(c)

			

			



def acceptNewConnections(sock, streamRequests, timedRequests, history):
		#Poll the socket to see if there are any clients awaiting connection
		ready = select.select([sock],[],[],0)
		readyToRead = ready[0]
		if(len(readyToRead)>0):
			connection, client_address = sock.accept()
			try:
				#Recieves a single byte to determine connection type
				requestType = connection.recv(1)
				if (requestType == b's'):
					#Connection is an unfiltered stream
					streamRequests.append((connection,None, [], [], [], [], [], []))
				elif(requestType == b'S'):
					#Connection is a filtered stream
					bitfields = recoverBitfield(connection)
					exeBlacklist = recoverList(connection)
					PIDBlacklist = recoverList(connection)
					IPBlacklist = recoverList(connection)
					exeWhitelist = recoverList(connection)
					PIDWhitelist = recoverList(connection)
					IPWhitelist = recoverList(connection)
					streamRequests.append((connection, bitfields, exeBlacklist, PIDBlacklist, IPBlacklist, exeWhitelist, PIDWhitelist, IPWhitelist))
				elif(requestType == b'b'):
					#Connection is a batch request by size
					num = connection.recv(4)
					num = int.from_bytes(num,byteorder='little')
					if(num <= len(history)):
						message = 'y'.encode('utf-8')
						connection.sendall(message)
						for x in range(0,num):
							item = history[x]
							message=struct.pack('i',len(item))
							message+=history[x]
							connection.sendall(message)
					else:
						connection.sendall('n'.encode('utf-8'))
				elif(requestType == b't'):
					#Connection is an unfiltered timed request
					num = connection.recv(4)
					num = int.from_bytes(num,byteorder='little')
					timedRequests.append((connection, time.time() + num, None, [], [], [], [], [], []))
				elif(requestType == b'T'):
					#Connection is a filtered timed request
					num = connection.recv(4)
					num = int.from_bytes(num,byteorder='little')
					bitfields = recoverBitfield(connection)
					exeBlacklist = recoverList(connection)
					PIDBlacklist = recoverList(connection)
					IPBlacklist = recoverList(connection)
					exeWhitelist = recoverList(connection)
					PIDWhitelist = recoverList(connection)
					IPWhitelist = recoverList(connection)
					timedRequests.append((connection, time.time() + num, bitfields,exeBlacklist,PIDBlacklist,IPBlacklist, exeWhitelist, PIDWhitelist, IPWhitelist))
			except socket.error as e:
				print(e)
				print("Failure when connecting to client. Shutting down...")
				sock.close()
				sys.exit(1)


if __name__ == '__main__':
	main()