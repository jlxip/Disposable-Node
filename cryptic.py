from random import randint
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()
unpad = lambda s: s[:-ord(s[len(s)-1:])]

def getCipher(key, IV):
    return AES.new(key, AES.MODE_CBC, IV)

def encrypt(key, IV, data):
    return getCipher(key, IV).encrypt(pad(data))

def decrypt(key, IV, data):
    return unpad(getCipher(key, IV).decrypt(data))

def genRandomString(length):
	return ''.join([chr(randint(0, 255)) for i in range(length)])

def genIV():
	return genRandomString(BS)

def genRandomAESKey():
	return genRandomString(32)	# 32 bytes (256 bits)

def getRSACipher(rawkey):
	return PKCS1_OAEP.new(RSA.importKey(rawkey))

def genPairOfKeys():
	priv = RSA.generate(4096)	# 4096 bytes, pretty good!
	pub = priv.publickey()
	return (priv.exportKey(), pub.exportKey())
