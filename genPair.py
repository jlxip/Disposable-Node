#!/usr/bin/env python2.7

import cryptic, os

if __name__ == '__main__':
	if os.path.isfile('priv.key') or os.path.isfile('pub.key'):
		print 'Keys already exist!'
		exit()

	priv, pub = cryptic.genPairOfKeys()

	with open('priv.key', 'w') as f:
		f.write(priv)
	with open('pub.key', 'w') as f:
		f.write(pub)

	print 'Done!'
