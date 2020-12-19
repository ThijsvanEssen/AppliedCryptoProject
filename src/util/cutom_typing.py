from typing import Tuple, List, Dict, TypedDict, Optional, Union
from socket import socket

# This file takes a functional approach to typing by using the alias function.

# Basi building blocks for typing.
Bit = int
Scalar = int
HexString = str

# Coordinates used in Montgomery and in Twisted Edward Curves
UCoordinate = int
VCoordinate = int
YCoordinate = int
XCoordinate = int

# Typing relevant for creating key pairs and sending messages.
EncodedPublicKey = str
EncodedPrivateKey = str

# Relevant typing for Montgomery values. A point is either express by (u,v) or by (u).
MontgomeryKey = UCoordinate
MontgomeryKeyPair = Tuple[Scalar, MontgomeryKey]
MontgomeryPoint = Union[Tuple[UCoordinate, VCoordinate], UCoordinate]
EncodedMontgomeryKeyPair = Tuple[EncodedPrivateKey, EncodedPublicKey]

# Relevant typing for Twisted Edward values.
TwistedEdwardKey = Tuple[YCoordinate, Bit]
TwistedEdwardKeyPair = Tuple[Scalar, TwistedEdwardKey]
TwistedEdwardPoint = Tuple[YCoordinate, XCoordinate]

# General typing for a point on a curve. Eiter a Twisted Edward point or a Montgomery point.
Point = Union[TwistedEdwardPoint, MontgomeryPoint]

# Typing relevant for indicating encoding or original format of a message.
Content = str
Message = HexString

# List of keys that can be used in the construction of the shared secret.
TemporalKeys = List[EncodedPublicKey]

# The shared secret that is created by running the X3DH protocol.
SharedSecret = Tuple[bytes, bytes]
# A dictionary that is used by the client to keep track of shared secret with other clients.
KnownKeys = Dict[EncodedPublicKey, Optional[SharedSecret]]


class UserInformation(TypedDict):
    """
    This class is used in defining the typing for a dictionary that is used by the server. This dictionary contains the
    information associated with a client.
    """
    queue: List[Message]
    spk: EncodedPublicKey
    sock: socket
    keys: Optional[TemporalKeys]


# A dictionary that is used by the server to keep track of the registered clients.
RegisteredUsers = Dict[EncodedPublicKey, UserInformation]

# Alias for a XEdDSA Signature.
Signature = Tuple[TwistedEdwardPoint, int]
