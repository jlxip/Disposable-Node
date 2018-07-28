# Disposable-Node

## Introduction
A node for Disposable. Which acts as an intermediary between clients.

This protects their IP, doesn't force the clients to open ports, and lets them use any proxy or VPN they want. For more information, [read the README of the client](https://git.jlxip.net/jlxip/Disposable-Client).

The node stores in a database (powered by SQLite) the identities. However, the "delayed" messages (those who could not be sent because the receiver wasn't connected) are not, they are stored in memory, so make sure only to close the node when it's absolutely necessary.

## How to run
To use it, first run `genPair.py`, which will generate the pair of asymmetric keys to establish each connection.

Then, run `gennodefile.py`, which will generate `node.dat`, the file that will have to be shared so that clients can connect to the node.

Finally, run `node.py` to boot up the node.

Make sure to have the port 3477 (or any of your choice, in which case change PORT at the top of `node.py` and `gennodefile.py`) open.

## The protocol
The Node has its own protocol. This is it:

Once the connection has been established, if `\x00` is sent to the node, it will just close the connection. This is a "ping" that the client makes when it's open to see if the node is up and running.

### Key exchange
The first thing the node does when it receives a connection is the key exchange.

The client randomly generates a symmetric key and an initialization vector (AES-CBC), which is encrypted with the node's public key and sent.

The node will decrypt with its private key the received data, and keep this values in memory for as long the connection is up.

Then, to check if the key has been sent properly, it will encrypt and send the string `OK`. If the client is unable to decrypt it, it will terminate the connection.

Beyond this point, all data will be encrypted with the symmetric key.

### Intentions
Once the keys have been exchanged, the client must send an intention (purpose) code.

- `\x00` is for creating a new identity.
- `\x01` is for using an existing identity.

#### New identity
In case `\x00` is sent to the node, the node will prepare for creating an identity. It will return `\x00`.
LO DEJO A MEDIAS, TENGO QUE CAMBIAR UNAS COSILLAS, LUEGO SIGO.