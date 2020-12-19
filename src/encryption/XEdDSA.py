from encryption.ECC import TwistedEdwardCurve25519

from util.protocol import Protocol
from util.cutom_typing import *

from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512

import re


class XEdDSA:
    """
    This class implements the necessary functions for signing messages and verifying signatures.

    Parameters:
        key_pair :: MontgomeryKeyPair - the key pair that is used for signing. The Twisted Edward key pair will be
            derived from this key pair.
        curve :: TwistedEdwardCurve - the Twisted Edward curve over which we perform our operations.
    """
    def __init__(self, key_pair: MontgomeryKeyPair, curve: TwistedEdwardCurve25519):
        self.mont_private, self.mont_public = key_pair
        self.curve = curve
        self.edward_private, self.edward_public = self.curve.calculate_key_pair_from_mont(self.mont_private)
        self.edward_public = self.curve.determine_x(*self.edward_public), self.edward_public[0]

    def sign(self, message: Message) -> Signature:
        """
        This methods handles the signing of a message. Since the key pair is already known by the XEdDSA class we only
        require the message as an input.

        Parameters:
            message :: Message - the message that will be placed directly in the content field of a protocol message.

        Returns:
            A tuple including a Twisted Edward Point and that will be used to recreate the Twisted Edward Point.
        """
        len_bytes = (2 ** self.curve.b_len - 2).to_bytes(64, "little")
        pri_bytes = self.edward_private.to_bytes(64, "little")
        mes_bytes = bytes(message, "utf-8")
        zet_bytes = get_random_bytes(64)

        sha_1 = SHA512.new(len_bytes)
        sha_1.update(pri_bytes + mes_bytes + zet_bytes)
        res = int(sha_1.hexdigest(), 16) % self.curve.q

        point_r = self.curve.scalar_multiplication(res, self.curve.b)
        rpt_bytes = point_r[0].to_bytes(64, "little") + point_r[1].to_bytes(64, "little")
        pub_bytes = self.edward_public[0].to_bytes(64, "little") + self.edward_public[1].to_bytes(64, "little")

        sha = SHA512.new()
        sha.update(rpt_bytes + pub_bytes + mes_bytes)
        hes = int(sha.hexdigest(), 16) % self.curve.q

        s = (res + hes * self.edward_private) % self.curve.q

        return point_r, s

    def verify(self, mont_public_key: MontgomeryKey, message: Message, signature: Signature) -> bool:
        """
        This method handles verification of a signature over a certain message. It takes the signature and splits it in
        its two parts. The point will be used to verify the newly calculated check with.

        Parameters:
            mont_public_key :: MontgomeryKey - the public key of the signer.
            message :: Message - the message that is signed
            signature :: Signature - the signature with the private key associated with the given public key over the
                provided message.

        Returns:
            The result of the verification.
        """
        r, s = signature
        if mont_public_key >= self.curve.p or r[0] >= 2 ** self.curve.p_bits or s >= 2 ** self.curve.q_bits:
            return False
        edward_public_key: TwistedEdwardKey = self.curve.from_montgomery_u(mont_public_key)
        public_key_point: TwistedEdwardPoint = (self.curve.determine_x(*edward_public_key), edward_public_key[0])
        if self.curve.on_curve(public_key_point):
            sha = SHA512.new()
            rpt_bytes = r[0].to_bytes(64, "little") + r[1].to_bytes(64, "little")
            pub_bytes = public_key_point[0].to_bytes(64, "little") + public_key_point[1].to_bytes(64, "little")
            mes_bytes = bytes(message, "utf-8")
            sha.update(rpt_bytes + pub_bytes + mes_bytes)
            h = int(sha.hexdigest(), 16) % self.curve.q

            sb = self.curve.scalar_multiplication(s, self.curve.b)
            ha = self.curve.scalar_multiplication(h, public_key_point)
            ha = (-ha[0], ha[1])
            r_check = self.curve.point_addition(sb, ha)
            return r == r_check

    @staticmethod
    def encode_signature(signature: Signature) -> HexString:
        """
        Method encodes a signature to a 192-character long hex string

        Parameters:
            signature :: Signature - the signature to be encoded.

        Returns
            Hexadecimal encoded signature.
        """
        r, s = signature
        return hex(r[0])[2:].zfill(64) + hex(r[1])[2:].zfill(64) + hex(s)[2:].zfill(64)

    @staticmethod
    def decode_signature(signature: HexString) -> Signature:
        """
        Method decodes 192-character long hex string to a signature.

        Parameters:
            signature :: HexString - the signature to be decoded.

        Returns
            Decoded signature.
        """
        sig_regex = re.compile(f"^{Protocol.address}{Protocol.address}{Protocol.address}$")
        x, y, s = sig_regex.search(signature).groups()
        return (int(x, 16), int(y, 16)), int(s, 16)
