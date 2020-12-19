from encryption.ECC import MontgomeryCurve25519, TwistedEdwardCurve25519
from encryption.XEdDSA import XEdDSA

from util.protocol import Protocol
from util.cutom_typing import *

from threading import Thread
from socket import AF_INET, SOCK_STREAM

import logging


class Server:
    """
    Class that implements the functionalities of the server for the specified protocol (@util.protocol). This is a bare
    version of the server and is intended as a proof-of-concept for the application.

    The type of the registered users is @util.custom_typing.RegisteredUsers. The layout of this dictionary is given in
    @util.custom typing. However, for convenience a quick schematic of the type is:

        {
            EncodedPublicKey:
                {
                    "queue": List[Message],
                    "spk": EncodedPublicKey,
                    "sock": socket
                    "keys": Optional[TemporalKeys]
                }
        }


    Parameters:
        host :: str - the host address for the server.
        port :: int - the port number used by the server.
        buff :: int - the size of the buffer used in the socket that connects with the clients.
        log_name :: str - the name of the optional logfile.
    """

    def __init__(self,
                 host: str = 'localhost',
                 port: int = 7000,
                 buff: int = 1024,
                 log_name: Optional[str] = None):
        # The dictionary that keeps track of the registered users.
        self.registered_users: RegisteredUsers = {}

        self.host: str = host
        self.port: int = port
        self.buff: int = buff
        self.addr: (str, str) = (self.host, self.port)
        self.serv: socket = socket(AF_INET, SOCK_STREAM)
        self.serv.bind(self.addr)

        # Set up the proper curves for our signature scheme and key generation.
        m = MontgomeryCurve25519()
        t = TwistedEdwardCurve25519()

        # Generate a key pair. The public key is also used as source address in all communication generated by the
        # server.
        private, self.public = m.generate_key_pair()
        keypair = (m.decode_scalar(private), m.decode_u_coordinate(self.public))

        # Set up the signature scheme for the server. Use the generated key pair.
        self.XEdDSA = XEdDSA(keypair, t)

        if log_name:
            logging.basicConfig(
                format='[%(levelname)s] %(asctime)s: %(message)s',
                filename=f'{log_name}.log',
                level=logging.DEBUG)

    def accept_incoming_message(self) -> None:
        """
        This method handles the initial connection of a client. There are two possibilities for connecting that need to
        be handled. The server will either receive a message of type NEWUSER or of type CONNECT. The former case is
        relevant for a completely new user. This user is not registered with the server. The following holds:
            >>> source not in self.registered_users
        The other case means that the user is already registered. However, we are now updating the socket information
        and possibly emptying the queue. This means that after both a NEWUSER and CONNECT message we have the following
        object stored for a client `source` connecting with socket `sock` with a spk that is the current one `content`.
            >>> self.registered_users[source] = UserInformation(queue=[], spk=content, sock=client, keys=None)
        """
        while True:
            # Accepting the connecting and receiving the first message.
            client, client_address = self.serv.accept()
            initial_message = client.recv(self.buff).decode("utf8")

            logging.info(f"{client_address[0]}:{client_address[1]} has connected.")
            logging.info(f"{initial_message = }")

            try:
                # Parse the message.
                m_type, (source, _, content, signature) = Protocol.parse(initial_message)
                # The user is not yet registered and wishes to do so.
                if source not in self.registered_users and m_type == Protocol.MessageTypes.NEWUSER:
                    self.registered_users[source] = UserInformation(
                        queue=[],
                        keys=None,
                        spk=content,
                        sock=client,
                    )
                    # Sign the server public key.
                    signature = XEdDSA.encode_signature(self.XEdDSA.sign(self.public))
                    # Send a message informing the client of the public key of the server.
                    message = Protocol.format_content(Protocol.MessageTypes.NEWUSER,
                                                      self.public,
                                                      source,
                                                      self.public,
                                                      signature)
                    self.send_to_socket(client, message)

                # The user is already known by the server and wishes to reconnect.
                if source in self.registered_users and m_type == Protocol.MessageTypes.CONNECT:
                    # Verify the signature of the user.
                    valid_signature = self.XEdDSA.verify(MontgomeryCurve25519.decode_u_coordinate(source),
                                                         content,
                                                         XEdDSA.decode_signature(signature))
                    if valid_signature:
                        # Only if they can proof their identity we will overwrite the previous session.
                        self.registered_users[source]["sock"] = client
                        # Deliver all messages to the messages that have been queued.
                        for i in range(len(self.registered_users[source]["queue"])):
                            self.send_to_socket(client, self.registered_users[source]["queue"][i])
                        # Ensure the message queue it empty again.
                        self.registered_users[source]["queue"] = []
                # Start the client handler that will handle communication with the client from here on.
                Thread(target=self.handle_client, args=(client, source,)).start()
            except AttributeError:
                # The message did not adhere to the protocol.
                self.handle_error(client, "50726f746f636f6c204572726f72")

    def handle_client(self, client: socket, source: EncodedPublicKey) -> None:
        """
        This method handles all communication with the client. It can receive messages of three types. It can handle
        Sending a message to another users (MESSAGE), it can handle a request for a spk of a user (REQUEST), and it can
        handle a message that indicates it is the initial message for shared secret generation (DIFFIE). The first and
        final message type are treated identically when it concerns the server. Both these message are simply passed
        along to the destination that is specified in the message. The middle message type (REQUEST) is handled
        differently. The server will respond with the spk associated with the requested input.

        Parameters:
            client :: socket - the socket object this client handler is responsible for.
            source :: EncodedPublicKey - the original public key of the client that started this session. This is used
                for verification and logging.
        """
        while True:
            try:
                message = client.recv(self.buff).decode("utf8")
                try:
                    # Parse the message.
                    m_type, (new_source, destination, content, signature) = Protocol.parse(message)
                    if source == new_source:
                        # The user uses the same public key.

                        # Dictionary containing the possible options for action the client handler can take.
                        switcher = {
                            Protocol.MessageTypes.REQUEST: Thread(target=self.handle_request, args=(
                                client, source, destination)),
                            Protocol.MessageTypes.MESSAGE: Thread(target=self.handle_message, args=(
                                client, source, destination, message)),
                            Protocol.MessageTypes.DIFFIE: Thread(target=self.handle_message, args=(
                                client, source, destination, message)),
                        }
                        # Start the relevant thread
                        switcher[m_type].start()
                    else:
                        # The user suddenly uses a different public key.
                        logging.warning(f"{source} attempted to spoof their identity.")
                except AttributeError:  # The message did not adhere to the protocol.
                    logging.warning(f"{source} failed to adhere to the protocol with the message: \n\t {message}")
                    # Pre encoded error message.
                    self.handle_error(client, "50726f746f636f6c204572726f723a20446973636f6e6e656374696e67")
                    client.close()
            except OSError:  # the client disconnected.
                logging.info(f"{source} disconnected.")
                client.close()

    def handle_message(self, client: socket,
                       source: EncodedPublicKey,
                       destination: EncodedPublicKey,
                       message: Message) -> None:
        """
        This method handles the messages of type MESSAGE and DIFFIE. It verifies that the source and the destination are
        registered on this server. If both conditions hold the server tries to send the message over the socket of the
        destination. If this socket is closed or it fails the message is added to the queue. This message will then be
        send on the next connection of the user to the server.

        Parameters:
            client :: socket - the socket of the source.
            source :: EncodedPublicKey - the public key of the source.
            destination :: EncodedPublicKey - the public key of the destination.
            message :: Message - the correctly formatted message send from source to destination.
        """
        if source not in self.registered_users:
            logging.warning(f"{source} tried to send while it is not registered.")
            self.handle_error(client, "43616e6e6f742073656e642066726f6d2061206e6f6e2d757365722e")
            return
        if destination not in self.registered_users:
            logging.warning(f"{source} tried to send while destination is not registered.")
            self.handle_error(client, "43616e6e6f742073657276652061206e6f6e2d757365722e")
            return
        # Retrieve the required socket for the destination

        self.send(destination, message)

    def handle_request(self, client: socket, source: EncodedPublicKey, target: EncodedPublicKey) -> None:
        """
        This method handle the messages of type REQUEST. It checks whether the destination is registered. If this is the
        case it returns the destination address and the associated spk to the user.

        Parameters:
            client :: socket - the socket of the source.
            source :: EncodedPublicKey - the public key of the source.
            target :: EncodedPublicKey - the public key of the target the source wishes to obtain the spk from.
        """
        if target not in self.registered_users:
            logging.warning(f"{source} tried to create a session while target is not registered.")
            self.handle_error(client, "55736572206973206e6f742072656769737465726564")
            return
        self.send_server_message(Protocol.MessageTypes.REQUEST,  # Message type REQUEST.
                                 source,  # To the requester (source).
                                 target + self.registered_users[target]["spk"])  # The requested spk.

    def handle_error(self, destination: socket, reason: HexString) -> None:
        """
        This method handles errors anywhere in the handling of a client. It receives a socket, this is to make sure the
        error message arrives and is not lost because of a wrong source (:: EncodedPublicKey) parameter given.
        
        Parameters:
            destination :: socket - the socket associated with the client that should receive an error message.
            reason :: HexString - a pre encoded error message that informs the client of their mishap.
        """
        # Create dummy data for the source, destination, and signature fields.
        s = d = "0" * 128
        sign = s * 3
        # Format the message according to the protocol.
        message = Protocol.format_content(Protocol.MessageTypes.ERROR, s, d, reason, sign)
        # Send the message.
        self.send_to_socket(destination, message)

    def send_server_message(self, m_type: Protocol.MessageTypes,
                            destination: EncodedPublicKey,
                            content: Content) -> None:
        """
        This method is a wrapper method for sending messages created by the server. This is relevant for the messages
        of type REQUEST.

        Parameters:
            m_type :: Protocol.MessageTypes - the type of the message that is being send. In this case it will be
                REQUEST
            destination :: EncodedPublicKey - the destination the server should send the message to.
            content :: Content - the actual useful information send by the server.

        # NOTE: For this protocol we could eliminate this method and simply move it's functionality to
        @handle_request(). However, since we prefer this to be a semi-scalable implementation we maintain the use of
        this method
        """
        # Create a proper signature and format the message inline with the protocol.
        signature = XEdDSA.encode_signature(self.XEdDSA.sign(content))
        message = Protocol.format_content(m_type, self.public, destination, content, signature)
        # Send the message.
        self.send(destination, message)

    def send(self, destination: EncodedPublicKey, message: Message) -> None:
        """
        This method handles sending a formatted message to a destination. If the socket is not available the method will
        put the message in the queue of the destination. The user associated with the destination will receive the
        message the next session they create.

        Parameters:
            destination :: EncodedPublicKey - the public key of the destination used to retrieve the right socket.
            message :: Message - the properly formatted message that is to be sent to the destination.
        """
        # Retrieve the socket associated with the destination.
        destination_socket = self.registered_users[destination]['sock']
        try:
            # Try to send the message of the socket.
            Server.send_to_socket(destination_socket, message)
        except OSError:  # This should only be None if the destination was a public key and they are currently offline.
            # If the sending fails add the message to the queue for the destination.
            self.registered_users[destination]["queue"].append(message)

    @staticmethod
    def send_to_socket(destination: socket, message: Message) -> None:
        """
        This message sends the message to the socket.

        Parameters:
            destination :: socket - the socket associated with the destination.
            message :: Message - the properly formatted message that is to be sent to the destination.

        Raises:
            OSError - if the socket is no longer valid this method will fail and indicate so by re-raising the OSError.
        """
        try:
            # Try sending the message over the socket.
            destination.send(bytes(message, "utf-8"))
        except OSError:
            # The socket is no longer available.
            raise

    def start_server(self) -> None:
        """
        This method starts the client. It connects to the server, sends the initial method and requests input from the
        user. The latter part would be replaced with a method of showing content in a proper application.
        """
        self.serv.listen(5)
        logging.info(f"Server started on {self.host}:{self.port}")
        accept_thread = Thread(target=self.accept_incoming_message)
        accept_thread.start()
        accept_thread.join()
        self.serv.close()


if __name__ == "__main__":
    # Create and start server.
    Server(log_name="logfile").start_server()
