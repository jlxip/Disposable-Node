# Disposable-Node

## Introduction
A node for Disposable. Which acts as an intermediary between clients.

This protects their IP, doesn't force the clients to open ports, and lets them use any proxy or VPN they want. For more information, [read the README of the client](https://git.jlxip.net/jlxip/Disposable-Client).

The node stores in a database (powered by SQLite) the identities. However, the "delayed" messages (those who could not be sent because the receiver wasn't connected) are not, they are stored in memory, so make sure only to close the node when it's absolutely necessary.

## How to run
To use it, first run `genPair.py`, which will generate the pair of asymmetric keys (RSA-4096) to establish each connection.

Then, run `gennodefile.py`, which will generate `node.dat`, the file that will have to be shared so that clients can connect to the node.

Finally, run `node.py` to boot up the node.

Make sure to have the port 3477 (or any of your choice, in which case change PORT at the top of `node.py` and `gennodefile.py`) open.

## The protocol
The Node has its own protocol. This is it:

Once the connection has been established, if `\x00` is sent to the node, it will just close the connection. This is a "ping" that the client makes when it's open to see if the node is up and running.

### Key exchange
The first thing the node does when it receives a connection is the key exchange.

The client randomly generates a symmetric key and an initialization vector (AES-256-CBC), which is encrypted with the node's public key and sent.

The node decrypts with its private key the received data, and keeps the values in memory for as long the connection is up.

Then, to check if the key has been sent properly, the node encrypts and sends the string `OK`. If the client is unable to decrypt it, it terminates the connection.

Beyond this point, all data is encrypted with the symmetric key.

### Intentions
Once the keys have been exchanged, the client sends an intention (purpose) code.

- `\x00` (all data) is for creating a new identity.
- `\x01` (first byte) is for using an existing identity.
- For any other byte, the node terminates the connection.

#### New identity
In case `\x00` is sent to the node, the node prepares for creating an identity, and returns `\x00`.

Then, both the client and the node enter in a loop (to prevent hash collisions, which, despite highly improbable, can happen).

The client generates a random pair of 4096-bits RSA keys, and sends the public key over the wire.

Then, the node receives the public key, and hashes it with MD5.

If the hash is not in use, the node returns `\x00` and stores both the hash (henceforth CID, Client Identity) and the public key in the database. Then, both the client and the node break the loop.

If the hash is in use, the node returns `\x01`, and both the client and the node go for another iteration of the loop.

#### Existing identity
In case `\x01` is the first byte the node receives, it prepares for authentication.

The rest of the data (from position one until the end) is the CID.

If the CID is not in the database, the node sends `\x01` and terminates the connection.

To verify whether the client is the owner of the given identity, the node generates a random 128 bytes long string, encrypts it with the public key of the CID, and sends the data to the client.

Then, the client decrypts the string with its private key, and sends it to the node.

The node now compares the raw string and the received.

If they match, `\x00` is sent to the client, and the intentions stage finishes.

If they don't match, `\x01` is sent to the client, and terminates the connection.

### Connection mode
Once the client is authenticated, it sends a "mode" code (like a second intention).

- `\x00` is for listening mode.
- `\x01` is for sending mode.
- `\x02` is for deletion mode.
- `\x03` is for public key request mode.
- For any other byte, the node terminates the connection.

#### Listening mode
In case `\x00` is sent to the node, the node appends the current socket, along with the AES symmetric key and the initialization vector of the transmission, to an array (_CONNECTIONS_), which will be used in the future to be sent new messages.

Then, the node looks for delayed messages sent to the CID of the client, and, if there are any, sends them now.

Finally, the node keeps the connection open (in this official implementation, by setting _CONNECTIONS_ as global, and managing each connection in an individual thread, so that, after the thread exits, the connection is not terminated).

#### Sending mode
In case `\x01` is sent to the node, the node enters in a loop, which won't be broken until either the client ends the connection or the node is closed.

For each iteration of the loop, the node awaits for incoming data (messages), which will be formatted according to the following structure:

```
{RECEIVER CID} | {RANDOM AES-256 KEY} | {CONTENT}
```

Both the random AES key and the content are encoded in base64, to keep the separations. The receiver CID is not encoded in base64 as it's always stored and displayed in hexadecimal.

Then, the node formats the message:
```
{CONNECTION CID (SENDER)} | {UTC UNIX TIMESTAMP} | {KEY} | {CONTENT}
```

Both the key and the content remain untouched. The sender CID is the CID of the client whose socket is in sending mode. The UTC unix timestamp will later be converted by the client into local time.

Next, the node tries to deliever the formatted message to the socket of the receiver which is in the listening mode.

In case it can't be sent (either because the receiver's socket in listening mode is closed or because there is none in memory), the message is appended to the delayed messages array, and will be sent to the receiver when a socket in listening mode is set.

Either if the message could be sent or not, the node goes for another iteration of the loop.