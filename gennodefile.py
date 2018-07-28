#!/usr/bin/env python2.7

import os, urllib2

if __name__ == '__main__':
	if os.path.isfile('node.dat'):
		print '\'node.dat\' already exists!'
		exit()
	if not os.path.isfile('pub.key'):
		print '\'pub.key\' not found. Please, run \'genPair.py\'.'
		exit()

	IP = urllib2.urlopen('https://wtfismyip.com/text').read().split('\n')[0]
	PORT = 3477

	with open('pub.key', 'r') as f:
		pub = f.read()

	with open('node.dat', 'w') as f:
		f.write(IP+':'+str(PORT)+'\n'+pub)

	print 'Done!'
