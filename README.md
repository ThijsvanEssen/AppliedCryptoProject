# Centralised Chat Application for Short and Localised Use.
_Requires Python3.8+_

This project was developed during the course applied cryptography at ELTE. The aim of the project is to creat a proof of
concept for a chat application that has basic cryptographic functionality. To this extent we base our selves on the 
Signal Protocol[[1](#1), [2](#2)]. We limit ourselves to these to part of the Signal protocol to manage the scope of the 
project.

## Running the Project
The project consists of two main classes. The Client and the Server. To set up a session we first start the server.
```
python ./server.py
```
This will create a server on localhost on port 7000. We can now connect clients simply by invoking them in the same way
as the server
```
python ./client.py
```

The server window will remain empty except on warning cases. A logging file is created standard under the name "logfile".
The client will immediately print it's initial session state, it's public key, and the required format for messaging. 
This is a proof of concept application so chatting is a bit of task, but straight forward. To send a message to client 
_A_ with public key _kA_ we simply type in the following in the window of the desired sender:
```
[kA] [message]
```
The message can contain spaces if so desired.

The application will now set up a session with the destination and send the message.

### Session State
To resume with an existing client we can start with a session state. The client class takes a _previous\_session_ as 
argument. This way we can continue with an already existing client. Trying it we can start two clients, save the state of 
one of the clients and immediately close it. Now in the other client we can send a message to the public key of the client
we just closed. If we initiate a new client with the saved session state we see that we will receive the message we had
just send from the other client.


## References
<a id="1">[1]</a> 
 M. Marlinspikea and T. Perrin. The X3DH Key Agreement Protocol. Signal Organisation, November 2016.


<a id="1">[2]</a> 
 T. Perrin. The XEdDSA and VXEdDSA Signature Schemes. Signal Organisation, October 2016



