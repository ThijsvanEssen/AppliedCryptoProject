from util.cutom_typing import *

from Crypto.Random import get_random_bytes
from math import log2, ceil


class EllipticCurve:
    """
    This class describes the basis of an Elliptic Curve as used throughout this application.

    Parameters:
        a :: int - the first scalar in the curve definition. In literature this is referred to as `a` for a Twisted
            Edward curve and `A` for the Montgomery curve.
        d :: int - the second scalar in the curve definition. Due to the definition of the curve this is not a required
            value for the Montgomery curve used.
        p :: int - the prime over which the field is created.
        base_point :: Point - the base point of the curve. This is a generator of the field.
    """

    def __init__(self, a: int, d: int, p: int, base_point: Point):
        self.a = a
        self.d = d
        self.p = p
        # Determine how many bits are needed to represent the prime number.
        self.p_bits = ceil(log2(p))
        # Determine number of bit needed for encoded points or integers.
        self.b_len = 8 * ceil((self.p_bits + 1) / 8)
        self.b = base_point

    def scalar_multiplication(self, scalar: Scalar, point: Point) -> Point:
        """
        Required method for all crypto applications that will be implemented.

        Parameters:
            scalar :: Scalar - an integer value that is the multiple of the point.
            point :: Point - a point on the curve that is to be added to itself `scalar` times.

        Returns:
            A new point on the curve the is scalar * point.
        """
        raise NotImplementedError()

    def on_curve(self, point: Point) -> bool:
        """
        This method checks whether a given point is on the curve. It does so by verifying that the point satisfies the
        the equation that defines the curve.
        """
        raise NotImplementedError()


class MontgomeryCurve25519(EllipticCurve):
    """
    This class implements the @EllipticCurve class and the functionalities of the Montgomery 25519 Curve. Furthermore,
    it implements the x25519 function (@MontgomeryCurve25519.scalar_multiplication()). The implementation is based on
    the description provided by Langley et al.[1]

    This curve satisfies the equation:
        v ** 2 = u ** 3 + A * u ** 2 + u.

    Parameters:
        a :: int - The first value in the equation. Denoted by `A` in the equation above.
        d :: int - This value is not needed in the Montgomery Curve definition.
        p :: int - The prime value.
        base_point :: MontgomeryPoint - The generator of the field.

    [1] https://www.ietf.org/rfc/rfc7748.txt
    """

    # This value is used for encoding en decoding UCoordinates and Scalars.
    _bits = 255

    def __init__(self,
                 a: int = 486662,
                 d: int = None,
                 p: int = pow(2, 255) - 19,
                 base_point: MontgomeryPoint =
                 (9, 14781619447589544791020593568409986887264606134616475288964881837755586237401)):
        super().__init__(a, d, p, base_point)
        self.a24 = (self.a - 2) // 4

    def scalar_multiplication(self, scalar: Scalar, u: MontgomeryPoint) -> UCoordinate:
        """
        This method implements the x25519 function as described in [1].

        Parameters:
            scalar :: Scalar - the amount of times the point will have to be added to itself.
            u :: MontgomeryPoint - a point on the Montgomery curve.

        Returns:
            A UCoordinate that represents a point that is on the Montgomery Curve. It is the point `scalar * u`.
        """
        x_1 = x_3 = u if type(u) != Tuple[UCoordinate, VCoordinate] else u[0]
        x_2 = z_3 = 1
        z_2 = swap = 0
        # From MSB to LSB.
        for b in bin(scalar)[2:]:
            # Determine whether we need to swap and update the value of swap.
            if swap ^ (swap := int(b)):
                x_2, x_3 = x_3, x_2
                z_2, z_3 = z_3, z_2
            # Perform derived Montgomery step operations.
            a = (x_2 + z_2) % self.p
            aa = pow(a, 2, self.p)
            b = (x_2 - z_2) % self.p
            bb = pow(b, 2, self.p)
            e = (aa - bb) % self.p
            c = (x_3 + z_3) % self.p
            d = (x_3 - z_3) % self.p
            da = (d * a) % self.p
            cb = (c * b) % self.p
            x_3 = ((da + cb) ** 2) % self.p
            z_3 = (x_1 * pow(da - cb, 2, self.p)) % self.p
            x_2 = (aa * bb) % self.p
            z_2 = (e * (aa + self.a24 * e)) % self.p
        # Final swap if necessary.
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2

        return (x_2 * pow(z_2, self.p - 2, self.p)) % self.p

    def generate_key_pair(self) -> EncodedMontgomeryKeyPair:
        """
        This method generates a valid Montgomery key pair that can be used by X3DH and by XEdDSA.

        Returns:
            An encoded key pair that can be decoded to a Twisted Edward Curve key pair.
        """
        t = TwistedEdwardCurve25519()
        private = ""
        public = ""
        valid = False
        while not valid:
            private = self.generate_scalar()
            pri_num = self.decode_scalar(private)
            pub_num = self.scalar_multiplication(pri_num, self.b[0])
            public = self.encode_u_coordinate(pub_num)

            public_key = t.from_montgomery_u(pub_num)
            edward_pub = (t.determine_x(*public_key), public_key[0])
            valid = t.scalar_multiplication(pri_num, t.b) == edward_pub
        return private, public

    def on_curve(self, point: MontgomeryPoint) -> bool:
        """
        This method tests whether the point satisfies the equation filled with the correct parameters.
            >>> v ** 2 == u ** 3 + self.a * u ** 2 + u

        Parameters:
            point :: MontgomeryPoint - a point with a u- and v-coordinate.

        Returns:
            The result of the check whether the point satisfies the equation.
        """
        u, v = point
        return (v ** 2) % self.p == (u ** 3 + self.a * u ** 2 + u) % self.p

    def encode_u_coordinate(self, u: UCoordinate) -> EncodedPublicKey:
        """
        This method encodes a u-coordinate to a hexadecimal string.

        Parameters:
             u :: UCoordinate - the coordinate to be encoded.

        Returns:
            A hexadecimal encoding of the u-coordinate.
        """
        u = u % self.p
        return ''.join([hex((u >> 8 * i) & 0xff)[2:].zfill(2) for i in range((MontgomeryCurve25519._bits + 7) // 8)])

    @staticmethod
    def generate_scalar() -> EncodedPrivateKey:
        """
        This method generates a an encoded private key for a Montgomery key pair.

        Returns:
            A hexadecimal encoding of a new scalar that can be used as private key.
        """
        return "".join(hex(b)[2:].zfill(2) for b in get_random_bytes(32))

    @staticmethod
    def decode_scalar(k: EncodedPrivateKey) -> Scalar:
        """
        This method takes an encoded private key and decodes it as specified in [1].

        Parameters:
            k :: EncodedPrivateKey - the hexadecimal encoding of a private key.

        Returns:
            A scalar value that can be used as a private key.
        """
        k_list = MontgomeryCurve25519.interpret_hex_string(k)
        k_list[0] &= 248
        k_list[31] &= 127
        k_list[31] |= 64
        return MontgomeryCurve25519.decode_little_endian(k_list)

    @staticmethod
    def decode_u_coordinate(u: EncodedPublicKey) -> UCoordinate:
        """
        This method takes an encoded public key and decodes it as specified in [1].

        Parameters:
            u :: EncodedPublicKey - the hexadecimal encoding of a public key.

        Returns:
            A u-coordinate value that can be used as a public key.
        """
        u_list = MontgomeryCurve25519.interpret_hex_string(u)
        if MontgomeryCurve25519._bits % 8:
            u_list[-1] &= (1 << (MontgomeryCurve25519._bits % 8)) - 1
        return MontgomeryCurve25519.decode_little_endian(u_list)

    @staticmethod
    def decode_little_endian(b: List[int]) -> int:
        """
        This method takes a list of integers and decodes them to a single little endian value as specified in [1].

        Parameters:
            b :: List[int] - the list of integers that should be interpreted as one little endian value.

        Returns:
            An integer that is the little endian interpretation of `b`.
        """
        return sum([b[i] << 8 * i for i in range((MontgomeryCurve25519._bits + 7) // 8)])

    @staticmethod
    def interpret_hex_string(hex_string: HexString) -> List[int]:
        """
        Interprets a hex string into separate bytes.

        Parameters:
            hex_string :: HexString - the string to be converted.

        Returns:
            List of bytes with a byte for every two hex digits.
        """
        return [int(hex_string[i:i + 2], 16) for i in range(0, len(hex_string), 2)]


class TwistedEdwardCurve25519(EllipticCurve):
    """
    This class implements the @EllipticCurve class and the functionalities required for the crypto suite. Furthermore,
    it implements the x25519 function (@TwistedEdwardCurve25519.scalar_multiplication()). The implementation is based on
    doubling and adding the point. Point addition is done as specified in [2].

    This curve satisfies the equation:
        a * x ** 2 + y ** 2 = 1 + d * x ** 2 * y ** 2.

    Parameters:
        a :: int - The first value in the equation. Denoted by `a` in the equation above.
        d :: int - The second value in the equation. Denoted by `d` in the equation above.
        p :: int - The prime value of the field.
        q :: int - The prime order of the generator.
        base_point :: TwistedEdwardPoint - The generator of the field.

    [2] https://pure.tue.nl/ws/portalfiles/portal/3850274/375386888374129.pdf
    """

    # This value is used for deriving a x-coordinate from a y-coordinate and a sign bit; (i^2 = -1 % self.p) holds.
    i = 19681161376707505956807079304988542015446066515923890162744021073123829784752

    def __init__(self,
                 a: int = -1,
                 d: int = -121665 * pow(121666, -1, 2 ** 255 - 19),
                 p: int = 2 ** 255 - 19,
                 q: int = 2 ** 252 + 27742317777372353535851937790883648493,
                 base_point: TwistedEdwardPoint =
                 (15112221349535400772501151409588531511454012693041857206046113283949847762202,
                  46316835694926478169428394003475163141307993866256225615783033603165251855960),
                 ):
        super().__init__(a, d, p, base_point)
        self.q = q
        # Determine how many bits are needed to represent the prime order.
        self.q_bits = ceil(log2(q))

    def scalar_multiplication(self, scalar: Scalar, point: TwistedEdwardPoint) -> TwistedEdwardPoint:
        """
        This method implements the x25519 function. It generates all doubled values needed to be added using
        @generate_multiples(). From here on it selects the required values and adds them together using the
        @point_addition() method.

        Parameters:
            scalar :: Scalar - the amount of times the point will have to be added to itself.
            point :: TwistedEdwardPoint - a point on the Twisted Edward curve.

        Returns:
            A TwistedEdwardPoint that represents a point that is on the Twisted Edward Curve. It is the point
            `scalar * point`.
        """
        # Generate as many doubled values for the point as required.
        points = self.generate_multiples(scalar, point)
        result = (0, 1)
        value = scalar
        # As long as we have not yet reached the end of the values to be added.
        while value:
            index = int(log2(value))
            # Add the required point to the result.
            result = self.point_addition(result, points[index])
            value -= 2 ** index
        return result

    def point_addition(self, point: TwistedEdwardPoint, other_point: TwistedEdwardPoint) -> TwistedEdwardPoint:
        """
        This method implements point addition as specified in [2].

        Parameters:
            point :: TwistedEdwardPoint - point 1 to be added.
            other_point :: TwistedEdwardPoint - point 2 to added.

        Returns:
            A new point that satisfies `point + other_point` as given in [2].

        """
        x_1 = point[0] * other_point[1] + point[1] * other_point[0]
        x_2 = 1 + self.d * point[0] * other_point[0] * point[1] * other_point[1]
        x = (x_1 * pow(x_2, -1, self.p)) % self.p
        y_1 = point[1] * other_point[1] - self.a * point[0] * other_point[0]
        y_2 = 1 - self.d * point[0] * other_point[0] * point[1] * other_point[1]
        y = (y_1 * pow(y_2, -1, self.p)) % self.p
        return x, y

    def generate_multiples(self, scalar: Scalar, point: TwistedEdwardPoint) -> List[TwistedEdwardPoint]:
        """
        This method determine the doubled values up to `log2(scalar)`. Using this we can effectively calculate point
        additions for high scalar values.

        Parameters:
            scalar :: Scalar - the amount of time the point will be added to itself later.
            point :: TwistedEdwardPoint - the point that is to be added scalar times to itself.

        Returns:
            A list of TwistedEdwardPoint where the index represents the doubling associated with the point. Index 0
            represent `point ** 0 == point`, 1: `point ** 1 == 2 * point`, 2: `point ** 2 == 4 * point` etc.
        """
        result = [point]
        for i in range(int(log2(scalar))):
            result.append(self.point_addition(result[i], result[i]))
        return result

    def on_curve(self, p: TwistedEdwardPoint) -> bool:
        """
        This method tests whether the point satisfies the equation filled with the correct parameters.
            >>> (self.a * p[0] ** 2 + p[1] ** 2) % self.p == (1 + self.d * p[0] ** 2 * p[1] ** 2) % self.p

        Parameters:
            p :: TwistedEdwardPoint - a point with a x- and y-coordinate.

        Returns:s
            The result of the check whether the point satisfies the equation.
        """
        return (self.a * p[0] ** 2 + p[1] ** 2) % self.p == (1 + self.d * p[0] ** 2 * p[1] ** 2) % self.p

    def determine_x(self, y: YCoordinate, s: Bit) -> XCoordinate:
        """
        This method determines the x-coordinate value based on a y-coordinate and a sign bit. The sign bit indicates
        whether the x-coordinate is positive or negative. We derive the x-coordinate from the y-coordinate by the
        following formula:
            x = -1 ** s * sqrt((y ** 2 - 1) / (self.d * y ** 2 - self.a))
        To implement this properly we first acknowledge that this method limits our implementation. While it can be
        extend to include other options this method only support curves for which holds
            >>> self.p % 8 == 5
        To this extent we use a predetermined value `TwistedEdwardCurve25519.i` for which the following holds:
            >>> (TwistedEdwardCurve25519.i ** 2) % self.p == -1 % self.p
        This is all in line with the methodology described in [2].

        Parameters:
            y :: YCoordinate - the y-coordinate for which we desire an x-coordinate.
            s :: Bit - the signifier whether the x-coordinate is positive (even) or negative (uneven).

        Returns:
            The x-coordinate associated with the given sign bit and y-coordinate such that:
                >>> self.on_curve((x, y))
        """
        # Determine the square of x.
        xx = (y ** 2 - 1) * pow(self.d * y ** 2 - self.a, -1, self.p) % self.p
        # Derive x from the power
        x = pow(xx, (self.p + 3) // 8 % self.p, self.p)
        sign = -1 ** s
        # Check if x is an actual square root.
        if (x * x) % self.p == xx:
            return (sign * x) % self.p
        elif (-x * x) % self.p == xx:
            return (sign * TwistedEdwardCurve25519.i * x) % self.p
        else:
            # x is no square root.
            raise ValueError

    def from_montgomery_u(self, u: UCoordinate) -> TwistedEdwardKey:
        """
        Convenience method for determining a y-coordinate and a sign-bit from a Montgomery u-coordinate.
        """
        return TwistedEdwardCurve25519.convert_to_twisted_edward(u, self.p, self.p_bits)

    def calculate_key_pair_from_mont(self, k: Scalar) -> Tuple[Scalar, TwistedEdwardKey]:
        """
        This method generates a Twisted Edward key pair based on a Montgomery private key pair.

        Parameters:
            k :: a Montgomery private key.

        Returns:
            A Twisted Edward key pair based on a Montgomery private key.
        """
        private_key = k % self.q
        e = self.scalar_multiplication(private_key, self.b)
        public_key = (e[1], 0)
        return private_key, public_key

    @staticmethod
    def convert_to_twisted_edward(u: UCoordinate, p: int, p_bits: int = None) -> TwistedEdwardKey:
        """
        This method converts a Montgomery u-coordinate to a Twisted Edward point encoded as a y-coordinate and a sign.

        Parameters:
            u :: the u-coordinate.
            p :: the order of the field.
            p_bits :: the amount of bits needed to encode p.

        Returns:
             The y-coordinate and sign-bit (0) for the given Montgomery u-coordinate.
        """
        p_bits = p_bits if p_bits else ceil(log2(p))
        u_masked = u % (2 ** p_bits)
        # Use the bi-rational mapping to transform the u-coordinate to a y-coordinate.
        y = ((u_masked - 1) * pow(u_masked + 1, -1, p)) % p
        return y, 0


if __name__ == "__main__":
    pass
