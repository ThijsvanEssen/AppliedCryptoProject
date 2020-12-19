from encryption.X3DH import ExtendedTripleDiffieHellman
from encryption.XEdDSA import XEdDSA
from encryption.ECC import MontgomeryCurve25519, TwistedEdwardCurve25519

from util.protocol import Protocol
from util.cutom_typing import *

from Crypto.Cipher import AES
from threading import Thread
from socket import AF_INET, SOCK_STREAM


class Client:
    """
    Class that handles the interaction with a server in the specified protocol (@util.protocol). It is a bare version
    that supports direct interaction for testing.

    Parameters:
        host :: str - the host address for the server that we are connecting to.
        port :: int - the port number used by the server that we are connecting to.
        buff :: int - the size of the buffer used in the socket that connects with the server.
        previous_session :: Optional[Tuple[MontgomeryKeyPair, MontgomeryKeyPair, KnownKeys]] -
            this is a possible parameter that specifies an existing session. This is useful for disconnecting and
            reconnecting if we want to maintain our identity.
    """

    def __init__(self,
                 host: str = 'localhost',
                 port: int = 7000,
                 buff: int = 1024,
                 previous_session: Optional[Tuple[MontgomeryKeyPair, MontgomeryKeyPair, KnownKeys]] = None,
                 ):

        self.host: str = host
        self.port: int = port
        self.buff: int = buff
        self.addr: (str, str) = (self.host, self.port)
        self.client: socket = socket(AF_INET, SOCK_STREAM)
        self.client.connect(self.addr)

        # Creating the necessary curves.
        # The Montgomery curve is used for encoding UCoordinates & X3DH. The UCoordinates are the public key for a user.
        self.montgomery_curve: MontgomeryCurve25519 = MontgomeryCurve25519()
        # The Twisted Edward curve is used for XEdDSA. This is the signature scheme used.
        twisted_edward_curve: TwistedEdwardCurve25519 = TwistedEdwardCurve25519()

        # The client will send a NEWUSER message when @initial_message() is called
        self.initial_message_type = Protocol.MessageTypes.NEWUSER

        if previous_session:  # if there is an existing session
            key_pair, spk_pair, known_keys = previous_session
            # The client will send a CONNECT message when @initial_message() is called
            self.initial_message_type = Protocol.MessageTypes.CONNECT

            # Set values appropriately.
            self.private_key, self.public_key = key_pair
            self.public_key_string = self.montgomery_curve.encode_u_coordinate(self.public_key)

            self.spk_private, self.spk_public = spk_pair
            self.public_spk_string = self.montgomery_curve.encode_u_coordinate(self.spk_public)

            self.known_keys: KnownKeys = known_keys
        else:  # if there is no existing session
            # All values are generated and initialised to new values.
            private_key_string, self.public_key_string = self.montgomery_curve.generate_key_pair()
            self.private_key = MontgomeryCurve25519.decode_scalar(private_key_string)
            self.public_key = MontgomeryCurve25519.decode_u_coordinate(self.public_key_string)

            self.private_spk_string, self.public_spk_string = self.montgomery_curve.generate_key_pair()
            self.spk_private = MontgomeryCurve25519.decode_scalar(self.private_spk_string)
            self.spk_public = MontgomeryCurve25519.decode_u_coordinate(self.public_spk_string)

            self.known_keys: KnownKeys = {}

        # Creating the encryption and Signature object for this client based on the proper curves and keys.
        self.X3DH = ExtendedTripleDiffieHellman((self.private_key, self.public_key), self.montgomery_curve)
        self.XEdDSA = XEdDSA((self.private_key, self.public_key), twisted_edward_curve)

        self.r_response: Dict[EncodedPublicKey: EncodedPublicKey] = {}

    @property
    def session(self):
        """
        Property that returns the current session. This is used as an optional argument in the
        """
        return (self.private_key, self.public_key), (self.spk_private, self.spk_private), self.known_keys

    def send_message(self, m_type: Protocol.MessageTypes, destination: EncodedPublicKey, content: Content) -> None:
        """
        This method handles sending message to a destination. The destination can either be another user or server.

        The method ensures that we create a shared secret with another user if it does not yet exist. This is done
        before any communication to ensure no eavesdropper can infer anything from the communication between two
        parties. Once - or if - the shared secret exists the method encrypts the content of the message and signs the
        content both in line with the Signal documentation.

        Parameters:
            m_type :: Protocol.MessageTypes - indicates the type of the message. Most relevant cases are:
                                                REQUEST: retrieving spk for the destination.
                                                MESSAGE: sending an encrypted message to a user.
                                                DIFFIE: sending the initial message in a session.
            destination :: EncodedPublicKey - the encoded public key of the destination. This is the identifier that
                the server uses to forward the message.
            content :: str                  - the actual content of a packet. This can be anything such as the message
                that the sender wants the receiver to be able to read.
        """
        content_prefix = ""  # Necessary for possible X3DH secret construction
        if destination not in self.known_keys and m_type != Protocol.MessageTypes.REQUEST:
            # Create the shared secret and setup for proper communication
            ek = self.handle_setting_up_session(destination)
            content_prefix = ek
            m_type = Protocol.MessageTypes.DIFFIE
        encrypted_content = ""  # The actual part that will be encrypted
        if m_type == Protocol.MessageTypes.MESSAGE or m_type == Protocol.MessageTypes.DIFFIE:
            # For the messages in the protocol that require encryption use the encryption and format the content.
            ad, sk = self.known_keys[destination]
            crypto = AES.new(sk, AES.MODE_EAX, ad)
            encrypted_bytes = crypto.encrypt(bytes(content, "utf-8"))
            encrypted_content = Protocol.bytes_to_hex(encrypted_bytes)
        total_content = content_prefix + encrypted_content  # The actual content that wil be incorporated.
        signature = XEdDSA.encode_signature(self.XEdDSA.sign(total_content))  # The signature of the content.
        message = Protocol.format_content(m_type, self.montgomery_curve.encode_u_coordinate(self.public_key),
                                          destination, total_content, signature)
        self.client.send(bytes(message, "utf8"))

    def send_initial_message(self) -> None:
        """
        This method is called once at the launch of the client. It communicates all necessary information to the server.
        The destination is fixed on the null address (\x00 * 32). This indicates the initial message since the public
        key of the server is not yet known. The content of the

        The client sends a message of type NEWUSER if it is the first time connecting (i.e. there is no previous session
        available). It sends a message of type CONNECT if there is a previous session defined during the setup of the
        client.
        """
        signature = self.XEdDSA.sign(self.montgomery_curve.encode_u_coordinate(self.spk_public))
        message = Protocol.format_content(self.initial_message_type,
                                          self.montgomery_curve.encode_u_coordinate(self.public_key),
                                          "0" * 64,
                                          self.montgomery_curve.encode_u_coordinate(self.spk_public),
                                          XEdDSA.encode_signature(signature))
        self.client.send(bytes(message, "utf8"))

    def handle_incoming(self) -> None:
        """
        This method is intended to be called in a separate thread an listen for incoming message that originate from the
        server.

        It reads the message on the socket and parses it to the correct sub parts. If the message does not parse the
        message is disregarded. An error is properly decoded and displayed to the client. This will happen if a message
        from the client did not adhere to the protocol.

        It handle the different message types properly.
            REQUEST responses are stored in the place the requester is waiting for them.
            ERROR the client will display the error so that the user can continue.
            DIFFIE it will correctly setup the secret if need be
            MESSAGE it will correctly decrypt the message if need be.

        Furthermore, it will verify the signature. While is some cases this might still cause the user to be susceptible
        for MITM-attacks we urge the reader to read the full report. However, in short; all public keys should be
        manually verified. This includes the key of the server. This means our MITM is now less likely as an attacker
        would need to obtain the secret key of the person they are impersonating.

        The verification of the public key can be made user-friendly with an additional interface layer on this client.
        """
        while True:
            message = self.client.recv(self.buff).decode("utf8")
            if not message:
                # In case the server closes the connection; close the socket and stop the process.
                self.client.close()
                break
            try:
                # Parse the message.
                m_type, (source, destination, content, signature) = Protocol.parse(message)
                # Handle error properly.
                if m_type == Protocol.MessageTypes.ERROR:
                    print(Protocol.hex_to_bytes(content).decode("utf-8"))
                # Only continue if we have a valid signature.
                if self.XEdDSA.verify(MontgomeryCurve25519.decode_u_coordinate(source),
                                      content,
                                      XEdDSA.decode_signature(signature)):
                    # Add the sources to the known keys. This is our address book.
                    if source not in self.known_keys:
                        self.known_keys[source] = None
                    # Handle incoming spk properly by storing the response for the requested public key.
                    if m_type == Protocol.MessageTypes.REQUEST:
                        self.r_response[content[:64]] = content[64:]
                    # Handle setting up a shared secret properly.
                    if m_type == Protocol.MessageTypes.DIFFIE:
                        content = self.handle_initial_key_message(source, content)
                    # Handle the decryption of any type of message that contains content properly.
                    if m_type == Protocol.MessageTypes.MESSAGE or m_type == Protocol.MessageTypes.DIFFIE:
                        # We can only continue if a shared secret exists.
                        if aes := self.known_keys[source]:
                            ad, sk = aes
                            crypto = AES.new(sk, mode=AES.MODE_EAX, nonce=ad)
                            content_bytes: bytes = Protocol.hex_to_bytes(content)
                            decrypted_message: bytes = crypto.decrypt(content_bytes)
                            # Print the decrypted message (:: bytes) in a nice fashion. This call would be replaced to
                            # print the content to a screen or nice window in an actual application.
                            Client.print_message(source, decrypted_message)
                        else:
                            print("ooh noes, there is no session!")  # Major panic.
            except AttributeError as ae:
                print(ae)

    def handle_initial_key_message(self, source: EncodedPublicKey, content: Content) -> str:
        """
        This method handles creating the shared secret from a message of type DIFFIE. It parses the content of the
        message into the ephemeral key part and the encrypted message part. The ephemeral key part is used in the
        construction of the shared secret while the encrypted message is returned as the new actual content of the
        message.

        Parameters:
             source :: EncodedPublicKey - the source of the message, this is used to ensure that the shared secret is
                known for the associated user. The associated user is the source as this is the party we now have a
                shared secret with.
             content :: str - the content of a message of type DIFFIE consists of two parts. The ephemeral key part and
                the encrypted message part.

        Returns:
            The actual content that the source intended send encrypted under the newly derived shared secret using AES.
        """
        try:
            ek_a, encrypted_message = Protocol.parse_diffie(content)
            ad, sk = self.X3DH.interpret_initial_message(MontgomeryCurve25519.decode_u_coordinate(source),
                                                         MontgomeryCurve25519.decode_u_coordinate(ek_a),
                                                         self.spk_private)
            self.known_keys[source] = ad, sk
            return encrypted_message
        except AttributeError:
            raise

    def handle_setting_up_session(self, destination: EncodedPublicKey) -> EncodedPublicKey:
        """
        This method handles creating the shared secret if the client wants to send a message and such a secret does not
        yet exist. It first requests the spk for the user it wants to send to from the server. After the request it
        the client waits till the server has responded. The handling of the response is done by @handle_incoming(). This
        method merely waits till the response is know by the client. Once it has obtained the spk the client has enough
        information to creat the shared secret. It does so and stores the information necessary for the shared secret.
        Additionally, it return the public ephemeral key so that this can be communicated to the other user.

        Parameters:
            destination :: EncodedPublicKey - the public key of the user we wish to set up a session with. This is used
                to retrieve the associated spk from the server

        Returns:
            The encoded version of the ephemeral public key associated with the private key used in the key generation.
        """
        self.send_message(Protocol.MessageTypes.REQUEST, destination, "")
        self.r_response[destination] = None
        while not (spk := self.r_response[destination]):
            #  Wait till the response has been processed and the spk is known to the client
            pass
        (ad, sk), ek = self.X3DH.generate_mutual_secret(MontgomeryCurve25519.decode_u_coordinate(destination),
                                                        MontgomeryCurve25519.decode_u_coordinate(spk))
        self.known_keys[destination] = ad, sk
        return ek

    @staticmethod
    def print_message(source: EncodedPublicKey, message: bytes) -> None:
        """
        Simple method for printing output to the command line. This would be replaced with a method of showing content
        in a proper application.
        """
        print("{}: \n\t {}".format(source, message.decode("utf-8")))

    def start_client(self) -> None:
        """
        This method starts the client. It connects to the server, sends the initial method and requests input from the
        user. The latter part would be replaced with a method of showing content in a proper application.
        """
        print(f"Public Key: {self.public_key_string}")
        accept_thread = Thread(target=self.handle_incoming)
        accept_thread.start()
        self.send_initial_message()

        # This is replaced in a proper application.
        print("input format: {destination_address} {message}")
        while True:
            m = input().split()
            des = m[0]
            mes = " ".join(m[1:])
            self.send_message(Protocol.MessageTypes.MESSAGE, des, mes)


if __name__ == '__main__':
    # Create a client with the standard parameters.
    client = Client()
    # Print the current session for easy testing.
    print(client.session)
    # Start the client.
    client.start_client()
