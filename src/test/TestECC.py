from encryption.ECC import *

import unittest


class TestMontgomery(unittest.TestCase):
    """
    Test vectors as presented in https://tools.ietf.org/html/rfc7748.
    """
    enc_scalar_1 = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
    dec_scalar_1 = 31029842492115040904895560451863089656472772604678260265531221036453811406496
    enc_u_coor_1 = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
    dec_u_coor_1 = 34426434033919594451155107781188821651316167215306631574996226621102155684838
    out_u_coor_1 = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"

    enc_scalar_2 = "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"
    dec_scalar_2 = 35156891815674817266734212754503633747128614016119564763269015315466259359304
    enc_u_coor_2 = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413"
    dec_u_coor_2 = 8883857351183929894090759386610649319417338800022198945255395922347792736741
    out_u_coor_2 = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"

    def setUp(self):
        self.curve = MontgomeryCurve25519()

    def test_base(self):
        point = self.curve.b
        self.assertTrue(self.curve.on_curve(point))

    def test_encode_u_coordinate(self):
        self.assertEqual(self.curve.encode_u_coordinate(TestMontgomery.dec_u_coor_1), TestMontgomery.enc_u_coor_1)
        self.assertEqual(self.curve.encode_u_coordinate(TestMontgomery.dec_u_coor_2), TestMontgomery.enc_u_coor_2)

        self.assertEqual(self.curve.encode_u_coordinate(
            MontgomeryCurve25519.decode_u_coordinate(TestMontgomery.enc_u_coor_1)),
            TestMontgomery.enc_u_coor_1)
        self.assertEqual(self.curve.encode_u_coordinate(
            MontgomeryCurve25519.decode_u_coordinate(TestMontgomery.enc_u_coor_2)),
            TestMontgomery.enc_u_coor_2)

    def test_decode_u_coordinate(self):
        self.assertEqual(MontgomeryCurve25519.decode_u_coordinate(TestMontgomery.enc_u_coor_1),
                         TestMontgomery.dec_u_coor_1)
        self.assertEqual(MontgomeryCurve25519.decode_u_coordinate(TestMontgomery.enc_u_coor_2),
                         TestMontgomery.dec_u_coor_2)

        self.assertEqual(MontgomeryCurve25519.decode_u_coordinate(
            self.curve.encode_u_coordinate(TestMontgomery.dec_u_coor_1)),
            TestMontgomery.dec_u_coor_1)
        self.assertEqual(MontgomeryCurve25519.decode_u_coordinate(
            self.curve.encode_u_coordinate(TestMontgomery.dec_u_coor_2)),
            TestMontgomery.dec_u_coor_2)

    def test_decode_scalar(self):
        self.assertEqual(MontgomeryCurve25519.decode_scalar(TestMontgomery.enc_scalar_1), TestMontgomery.dec_scalar_1)
        self.assertEqual(MontgomeryCurve25519.decode_scalar(TestMontgomery.enc_scalar_2), TestMontgomery.dec_scalar_2)

    def test_scalar_multiplication(self):
        result_1 = self.curve.scalar_multiplication(TestMontgomery.dec_scalar_1, TestMontgomery.dec_u_coor_1)
        self.assertEqual(self.curve.encode_u_coordinate(result_1), TestMontgomery.out_u_coor_1)
        result_2 = self.curve.scalar_multiplication(TestMontgomery.dec_scalar_2, TestMontgomery.dec_u_coor_2)
        self.assertEqual(self.curve.encode_u_coordinate(result_2), TestMontgomery.out_u_coor_2)


class TestTwistedEdward(unittest.TestCase):

    def setUp(self):
        self.curve = TwistedEdwardCurve25519()

    def test_base(self):
        point = (0, 1)
        point_2 = self.curve.b
        point_3 = self.curve.point_addition(point, point_2)
        self.assertTrue(self.curve.on_curve(point))
        self.assertTrue(self.curve.on_curve(point_2))
        self.assertTrue(self.curve.on_curve(point_3))

    def test_scalar_multiplication(self):
        self.assertEqual(self.curve.scalar_multiplication(1, self.curve.b), self.curve.b)
