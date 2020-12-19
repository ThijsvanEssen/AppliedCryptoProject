from encryption.X3DH import DiffieHellman, ExtendedTripleDiffieHellman
from encryption.ECC import MontgomeryCurve25519

import unittest


class TestDiffieHellman(unittest.TestCase):
    """
    Test vectors as presented in https://tools.ietf.org/html/rfc7748.
    """
    secret_key_alice = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    public_key_alice = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"

    secret_key_bob = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    public_key_bob = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"

    shared_secret = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

    def setUp(self):
        self.curve = MontgomeryCurve25519()
        self.diffie = DiffieHellman(self.curve)

    def test_commutative(self):
        a = 3
        b = 7
        c = 9
        a_ = self.diffie.run(a, c)
        b_ = self.diffie.run(b, c)
        self.assertEqual(self.diffie.run(b, a_), self.diffie.run(a, b_))

    def test_public_key(self):
        a = MontgomeryCurve25519.decode_scalar(TestDiffieHellman.secret_key_alice)
        b = MontgomeryCurve25519.decode_scalar(TestDiffieHellman.secret_key_bob)

        a_p = MontgomeryCurve25519.decode_u_coordinate(TestDiffieHellman.public_key_alice)
        b_p = MontgomeryCurve25519.decode_u_coordinate(TestDiffieHellman.public_key_bob)

        self.assertEquals(self.curve.scalar_multiplication(a, self.curve.b[0]), a_p)
        self.assertEquals(self.curve.scalar_multiplication(b, self.curve.b[0]), b_p)

        secret_a = self.curve.scalar_multiplication(a, b_p)
        secret_b = self.curve.scalar_multiplication(b, a_p)

        self.assertEquals(secret_a, secret_b)
        self.assertEquals(secret_a, MontgomeryCurve25519.decode_u_coordinate(TestDiffieHellman.shared_secret))


class TestExtendedThreeWayDiffieHellman(unittest.TestCase):

    def setUp(self):
        self.curve = MontgomeryCurve25519()
        self.a = MontgomeryCurve25519.decode_scalar(TestDiffieHellman.secret_key_alice)
        self.b = MontgomeryCurve25519.decode_scalar(TestDiffieHellman.secret_key_bob)

        self.a_p = MontgomeryCurve25519.decode_u_coordinate(TestDiffieHellman.public_key_alice)
        self.b_p = MontgomeryCurve25519.decode_u_coordinate(TestDiffieHellman.public_key_bob)

        self.diffie_a = ExtendedTripleDiffieHellman((self.a, self.a_p), self.curve)
        self.diffie_b = ExtendedTripleDiffieHellman((self.b, self.b_p), self.curve)

    def test_random_key(self):
        s_s, s_p = self.curve.generate_key_pair()
        private = self.curve.decode_scalar(s_s)
        public = self.curve.decode_u_coordinate(s_p)
        share_a, e_s = self.diffie_a.generate_mutual_secret(self.b_p, public)
        e = self.curve.decode_u_coordinate(e_s)
        share_b = self.diffie_b.interpret_initial_message(self.a_p, e, private)
        self.assertEquals(share_a, share_b)

    def test_public_private_pairs(self):
        kp_1 = (50076832903436978312758697924080601108551463093325015614560935105290702353376,
                7990661435862654295989030363949047204073993919133546629573407842381754001103)
        kp_2 = (49283830719704896105563393316140667590186179856650394754052202022567736389432,
                51242170616168093919539944766408269908738027244722995047835554441004047059844)
        kp_3 = (49585870203900394224270365994615377648433892482662875488651791560211197216560,
                45750684541307629782117088394775720690423490839048501825433587909445320218939)

        kps = [kp_1, kp_2, kp_3]

        for s, p in kps:
            share_a, e_s = self.diffie_a.generate_mutual_secret(self.b_p, p)
            e = self.curve.decode_u_coordinate(e_s)
            share_b = self.diffie_b.interpret_initial_message(self.a_p, e, s)
            self.assertEqual(share_a, share_b)

    @unittest.expectedFailure
    def test_random_pairs(self):
        kp_1 = (5,
                9)
        kp_2 = (23456789098765432345678,
                51242170616168093919539944766408269908738027244722995047835554441004047059844)

        kps = [kp_1, kp_2]

        for s, p in kps:
            share_a, e_s = self.diffie_a.generate_mutual_secret(self.b_p, p)
            e = self.curve.decode_u_coordinate(e_s)
            share_b = self.diffie_b.interpret_initial_message(self.a_p, e, s)
            self.assertEqual(share_a, share_b)
