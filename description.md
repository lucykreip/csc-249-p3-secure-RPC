# Overview of Application
This application models a secure client and server interaction through a VPN, using a TLS handshake and a class modeling the certificate authority to share a symmetric key so the client and server can encrypt and decrypt their messages to communicate securely in a efficient manner. In this application, the server echoes back the client's message in all uppercase. 

# Format of unsigned certificate
An unsigned certificate is formatted as 'SERVER_IP|SERVER_PORT|PUBLIC_KEY'. An example would be '127.0.0.1|65432|(45278, 56533)'. 

# Example Output
If the client sends the message 'Hello, World' the output is 'HELLO, WORLD'

# TLS handshake steps

First, the server sends its socket information and public key to the certificate authority (CA) so that the CA can confirm that the server's public key belongs to them as they say it does. The CA then encrypts a nonce to send to the server which the server then decrypts with its private key and sends the nonce back to the CA. This confirms to the CA that the socket information and public key match and the server is who its says it is. The CA then sends the signed certificate to the server which the server then sends to the client. It is decrypted with the CA's private key which proves they are confident in the server's identity. The client then encrypts the certificate with the CA's public key to get the certificate. Then the client encrypts a secret random value, the symmetric key, with the server's public key and sends it as a challenge. The server can decrypt this value with their private key and then both parties have the symmetric key and can communicate securely using symmetric key cryptography.

# Failure for real security

The asymmetric key generation scheme is not secure as someone supplies the number p that is passed into the function, and the private key is found by subtracting the random public key value from p. This means that is someone knew the random value generated, they could easily find the private key on their own, allowing them to access messages sent to the client. 



# Command Line Trace

## Certificate Authority
Certificate Authority started using public key '(5367, 56533)' and private key '51166'
Certificate authority starting - listening for connections at IP 127.0.0.1 and port 55553
Connected established with ('127.0.0.1', 50515)
Received client message: 'b'$127.0.0.1|65432|(51842, 56533)'' [31 bytes]
Signing '127.0.0.1|65432|(51842, 56533)' and returning it to the client.
Received client message: 'b'done'' [4 bytes]
('127.0.0.1', 50515) has closed the remote connection - listening 
Connected established with ('127.0.0.1', 50532)
Received client message: 'b'key'' [3 bytes]
Sending the certificate authority's public key (5367, 56533) to the client
Received client message: 'b'done'' [4 bytes]
('127.0.0.1', 50532) has closed the remote connection - listening 
^CCertificate authority is done!

## Secure Server

Generated public key '(51842, 56533)' and private key '4691'
Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Prepared the formatted unsigned certificate '127.0.0.1|65432|(51842, 56533)'
Connection established, sending certificate '127.0.0.1|65432|(51842, 56533)' to the certificate authority to be signed
Received signed certificate 'D_(51166, 56533)[127.0.0.1|65432|(51842, 56533)]' from the certificate authority
server starting - listening for connections at IP 127.0.0.1 and port 65432
Connected established with ('127.0.0.1', 50534)
Sending signed certificate to ('127.0.0.1', 50534)
Recieved symmetric key from ('127.0.0.1', 50534)
TLS handshake complete: established symmetric key '93992', acknowledging to client
Received client message: 'b'HMAC_6978[symmetric_93992[Hello, world]]'' [40 bytes]
Decoded message 'Hello, world' from client
Responding 'HELLO, WORLD' to the client
Sending encoded response 'HMAC_52525[symmetric_93992[HELLO, WORLD]]' back to the client
server is done!

## VPN

VPN starting - listening for connections at IP 127.0.0.1 and port 55554
Connected established with ('127.0.0.1', 50533)
Received client message: 'b'127.0.0.1~IP~65432~port~TLS request'' [35 bytes]
connecting to server at IP 127.0.0.1 and port 65432
server connection established, sending message 'TLS request'
message sent to server, waiting for reply
Received server response: 'b'D_(51166, 56533)[127.0.0.1|65432|(51842, 56533)]'' [48 bytes], forwarding to client
Received client message: 'b'E_(51842, 56533)[93992]'' [23 bytes], forwarding to server
Received server response: 'b"symmetric_93992[Symmetric key '93992' received]"' [47 bytes], forwarding to client
Received client message: 'b'HMAC_6978[symmetric_93992[Hello, world]]'' [40 bytes], forwarding to server
Received server response: 'b'HMAC_52525[symmetric_93992[HELLO, WORLD]]'' [41 bytes], forwarding to client
VPN is done!

## Secure Client

Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Connection established, requesting public key
Received public key (5367, 56533) from the certificate authority for verifying certificates
Client starting - connecting to VPN at IP 127.0.0.1 and port 55554
Requesting TLS handshake from server, waiting for signed certificate
Received signed certificate from server, verifying certificate
Verified certificate, extracting server's public key, IP address, and port
Generating a symmetric key
Sending symmetric key to server
TLS handshake complete: sent symmetric key '93992', waiting for acknowledgement
Received acknowledgement 'Symmetric key '93992' received', preparing to send message
Sending message 'HMAC_6978[symmetric_93992[Hello, world]]' to the server
Message sent, waiting for reply
Received raw response: 'b'HMAC_52525[symmetric_93992[HELLO, WORLD]]'' [41 bytes]
Decoded message 'HELLO, WORLD' from server
client is done!

# Message Format

Client --> Server: 'Hello, World' or some other string

Server --> Client: 'HELLO, WORLD'