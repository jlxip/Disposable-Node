#!/usr/bin/env python2.7

import socket, data, cryptic, os, base64, datetime, hashlib
from threading import Thread

PORT = 3477
SIMULTANEOUS_CONNECTIONS = 1024

def checkClient(con, thisAES, thisIV):
	global IDENTITIES
	data.send_msg(con, cryptic.encrypt(thisAES, thisIV, 'OK'))	# Ready to receive the CID
	CID = cryptic.decrypt(thisAES, thisIV, data.recv_msg(con))
	if not CID in IDENTITIES:
		data.send_msg(con, cryptic.encrypt(thisAES, thisIV, '\x01'))	# Inexisting client.
		return False
	check = cryptic.genRandomString(128)	# Generate a random string to check if the client is indeed the owner of the CID.
	data.send_msg(con, cryptic.encrypt(thisAES, thisIV, cryptic.getRSACipher(IDENTITIES[CID]).encrypt(check)))	# Send the check encrypted.
	if cryptic.decrypt(thisAES, thisIV, data.recv_msg(con)) == check:
		data.send_msg(con, cryptic.encrypt(thisAES, thisIV, '\x00'))
		return CID
	else:
		data.send_msg(con, cryptic.encrypt(thisAES, thisIV, '\x01'))
		return False

def manage(con):
	# Before anything, let's see if the client is just pinging
	r = data.recv_msg(con)
	if r == '\x00':	# Hi, you there?
		con.close()
		return

	# KEY SHARING
	global priv
	r = priv.decrypt(r)	# Decrypt the received message (key + IV)
	thisAES = r[:32]
	thisIV = r[32:]
	data.send_msg(con, cryptic.encrypt(thisAES, thisIV, 'OK'))	# Send 'OK' with the received key

	# INTENTIONS
	global IDENTITIES
	intention = cryptic.decrypt(thisAES, thisIV, data.recv_msg(con))
	CID = ''
	if intention == '\x00':
		# NEW
		data.send_msg(con, cryptic.encrypt(thisAES, thisIV, '\x00'))
		while True:
			PUB = cryptic.decrypt(thisAES, thisIV, data.recv_msg(con))
			CID = hashlib.md5(PUB).hexdigest()
			if CID in IDENTITIES:
				# There is already an identity with the same hash.
				data.send_msg(con, cryptic.encrypt(thisAES, thisIV, '\x01'))
			else:
				# Ready.
				data.send_msg(con, cryptic.encrypt(thisAES, thisIV, '\x00'))
				IDENTITIES[CID] = PUB
				break
		con.close()
		return
	elif intention == '\x01':
		# AUTHENTICATE
		CID = checkClient(con, thisAES, thisIV)
		if not CID:
			con.close()
			return
	else:
		con.close()
		return

	# Client identified.
	global CONNECTIONS
	global DELAYED

	try:
		mode = cryptic.decrypt(thisAES, thisIV, data.recv_msg(con))
	except:
		con.close()
		return
	if mode == '\x00':
		# LISTENING MODE
		CONNECTIONS[CID] = [con, thisAES, thisIV]

		if CID in DELAYED:
			# Send delayed messages
			for i in DELAYED[CID]:
				data.send_msg(con, cryptic.encrypt(thisAES, thisIV, i))
			DELAYED.pop(CID, None)	# Remove them

		# Now, the socket, as it's stored in a global variable, will remain open after the thread exits.
		# It will be used in the future to be sent messages.
	elif mode == '\x01':
		# SENDING MODE
		while(True):
			try:
				recv = cryptic.decrypt(thisAES, thisIV, data.recv_msg(con))
			except:
				break
			msg_from = CID
			msg_to = recv.split('|')[0]
			msg_time = int(datetime.datetime.utcnow().strftime('%s'))	# UTC. The client will adjust it to local time
			msg_content = recv.split('|')[1]	# It's in base64, but there's no need to decode it.
			# Remember: "int(time.time()) - Ans" to get the delay in seconds

			tosend = msg_from+'|'+msg_time+'|'+msg_content
			try:
				# Assumes the receiver is connected. If not, goes to except.
				msg_to_connection = CONNECTIONS[msg_to]
				data.send_msg(msg_to_connection[0], cryptic.encrypt(msg_to_connection[1], msg_to_connection[2], tosend))
			except:
				# If the message failed to send, just in case, to free memory, remove the entry from CONNECTIONS
				CONNECTIONS.pop(CID, None)
				# Leave it in the delayed list
				if not msg_to in DELAYED:
					DELAYED[msg_to] = []
				DELAYED[msg_to].append(tosend)
	elif mode == '\x02':
		# DELETE
		IDENTITIES.pop(CID, None)
		data.send_msg(con, cryptic.encrypt(thisAES, thisIV, '\x00'))
		con.close()
	else:
		con.close()

if __name__ == '__main__':
	if not os.path.isfile('priv.key'):
		print '\'priv.key\' not found. Please, run \'genPair.py\'.'
		exit()
	global priv
	with open('priv.key', 'r') as f:
		priv = f.read()
	priv = cryptic.getRSACipher(priv)

	global IDENTITIES
	global CONNECTIONS
	global DELAYED
	IDENTITIES = {}
	CONNECTIONS = {}
	DELAYED = {}

	ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	ss.bind(('', PORT))
	ss.listen(SIMULTANEOUS_CONNECTIONS)

	while True:
		try:
			con, _ = ss.accept()
		except:
			break
		Thread(target=manage, args=(con,)).start()
