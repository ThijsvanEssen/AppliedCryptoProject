from encryption.XEdDSA import XEdDSA
from encryption.ECC import TwistedEdwardCurve25519, MontgomeryCurve25519

import unittest


class TestXEdDSA(unittest.TestCase):
    a = ('8e317b854aa6cdd70e9233c5b75670bcfe8e74069e8e0acbf4b63503b94718d5',
         '14ca8a00364ef5f947836ae98ec584e42bbef2992ba2d826eeda162c61747054')
    b = ('832bad0f0192b7683180ef4fef7e45f43ea283e240071b9ff37693aeaff9fae3',
         '4cd9cd07c0f3029a21de422c52bd28d2457fa561e3cd65eb57ef2e89f6396030')

    message = "TestMessage."
    message_ = "NotTestMessage."

    def setUp(self):
        self.curve = TwistedEdwardCurve25519()
        self.a = MontgomeryCurve25519.decode_scalar(TestXEdDSA.a[0])
        self.b = MontgomeryCurve25519.decode_scalar(TestXEdDSA.b[0])

        self.a_p = MontgomeryCurve25519.decode_u_coordinate(TestXEdDSA.a[1])
        self.b_p = MontgomeryCurve25519.decode_u_coordinate(TestXEdDSA.b[1])

        self.sign_a = XEdDSA((self.a, self.a_p), self.curve)
        self.sign_b = XEdDSA((self.b, self.b_p), self.curve)

    def test_random_key(self):
        signature = self.sign_a.sign(TestXEdDSA.message)

        self.assertTrue(self.sign_a.verify(self.a_p, TestXEdDSA.message, signature))
        self.assertTrue(self.sign_b.verify(self.a_p, TestXEdDSA.message, signature))
        self.assertFalse(self.sign_a.verify(self.a_p, TestXEdDSA.message_, signature))
        self.assertFalse(self.sign_b.verify(self.a_p, TestXEdDSA.message_, signature))

    def test_encode_decode(self):
        signature = ((1, 1), 1)
        encoded = XEdDSA.encode_signature(signature)
        decoded = XEdDSA.decode_signature(encoded)
        self.assertEqual(len(encoded), 192)
        self.assertEqual(signature, decoded)

        signature = self.sign_a.sign(TestXEdDSA.message)
        encoded = XEdDSA.encode_signature(signature)
        decoded = XEdDSA.decode_signature(encoded)
        self.assertEqual(len(encoded), 192)
        self.assertEqual(signature, decoded)
