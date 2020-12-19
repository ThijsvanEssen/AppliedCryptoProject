from util.cutom_typing import *

from enum import Enum

import re


class Protocol:
    """
    Class that describes the Protocol and used for convenience. See report for full explanation on different message
    types.
    """
    class MessageTypes(Enum):
        CONNECT = 'C',
        NEWUSER = 'N',
        MESSAGE = 'M',
        REQUEST = 'R',
        DIFFIE = 'D',
        ERROR = 'E',

    switcher = {
        'C': MessageTypes.CONNECT,
        'N': MessageTypes.NEWUSER,
        'M': MessageTypes.MESSAGE,
        'R': MessageTypes.REQUEST,
        'D': MessageTypes.DIFFIE,

        'E': MessageTypes.ERROR,
    }

    address = r'([0-9a-f]{64})'  # 32-byte encoding of a public key.
    m_type = r'(C|N|M|R|D|E)'  # One letter encoding as depicted in @switcher.
    content = r'([0-9a-f]*)'  # Hex encoded content, can be as long as desired.
    signature = r'([0-9a-f]{192})'  # 96-byte encoding for the signature
    signifier = ':s:'  # The signifier that the content has ended and the signature starts.

    # The format for a message in the protocol.
    message_regex = re.compile(f'{address}{address}{m_type}{content}{signifier}{signature}')
    diffie_regex = re.compile(f'{address}{content}')

    @staticmethod
    def parse(message: Message) -> Tuple[MessageTypes, Tuple[EncodedPublicKey, EncodedPublicKey, Message, Message]]:
        """
        Use the specified regex to parse a message that has been send.

        Parameters:
            message :: Message - the message that is to be interpreted.

        Returns:
            The interpreted version of the message. The first element of the tuple is the message type. The second is a
            tuple that contains all data contained in the message.

        Raises:
            AttributeError - if the message is not properly formatted it re-raises the AttributeError generated by the
                regex.
        """
        try:
            source, destination, message_type, message, signature = Protocol.message_regex.search(message).groups()
            return Protocol.switcher[message_type], (source, destination, message, signature)
        except AttributeError:
            raise

    @staticmethod
    def format_content(m_type: MessageTypes,
                       source: EncodedPublicKey,
                       destination: EncodedPublicKey,
                       content: Message,
                       signature: Message) -> Message:
        """
        This method formats all data required for a message according to the specified protocol. Note that it insert the
        proper values where required and the signifier to ensure other parties can properly decode the message.

        Parameters:
            m_type :: MessageTypes - the type for this message, will result in a single letter.
            source :: EncodedPublicKey - used as is for the source argument of the message.
            destination :: EncodedPublicKey - used as is for the destination argument of the message.
            content :: Message - used as is for the contents argument of the message.
            signature :: Message - used as is for the signature argument of the message.

        Returns:
            Properly formatted string that represents the message.
        """
        return f"{source}{destination}{m_type.value[0]}{content}{Protocol.signifier}{signature}"

    @staticmethod
    def parse_diffie(message: Message) -> Tuple[EncodedPublicKey, Message]:
        """
        Use the diffie regex to parse a message that is the initial message in a session.

        Parameters:
            message :: Message - the message consisting of an ephemeral key and the first encrypted content.

        Return:
            The interpreted version of the message consisting of the ephemeral key and the first encrypted content.

        Raises:
            AttributeError - if the message is not properly formatted it re-raises the AttributeError generated by the
                regex.
        """
        try:
            a = Protocol.diffie_regex.search(message).groups()
            print(a)
            ephemeral_key, encrypted_message = Protocol.diffie_regex.search(message).groups()
            return ephemeral_key, encrypted_message
        except AttributeError:
            raise

    @staticmethod
    def bytes_to_hex(byte_string: bytes) -> HexString:
        """
        Method used to encode bytes to hex.

        Parameters:
            byte_string :: bytes - the string to be converted.

        Returns:
            Hexadecimal representation of `byte_string`.
        """
        return "".join(hex(byte)[2:].zfill(0) for byte in byte_string)

    @staticmethod
    def hex_to_bytes(hex_string: HexString) -> bytes:
        """
        Method used to decode hex to bytes.

        Parameters:
            hex_string :: HexString - the string to be converted.

        Returns:
            Byte representation of `hex_string`.
        """
        return b"".join(int(hex_string[i:i + 2], 16).to_bytes(1, "big") for i in range(0, len(hex_string), 2))