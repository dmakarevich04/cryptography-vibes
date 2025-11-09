import random
from elliptic_curve_utils import EllipticCurve


class ElGamal:
    def __init__(self, curve: EllipticCurve):
        self.curve = curve

    def generate_keys(self):
        private_key = random.randrange(1, self.curve.q)
        public_key = self.curve.point_mul(private_key, self.curve.P)
        return private_key, public_key

    def encode_block_to_point(self, block: bytes):
        data = bytes([len(block)]) + block
        m = int.from_bytes(data, 'big')
        for j in range(10000):
            x = (m * 10000 + j) % self.curve.p
            y_sqr = (pow(x, 3, self.curve.p) + self.curve.a * x + self.curve.b) % self.curve.p
            if pow(y_sqr, (self.curve.p - 1) // 2, self.curve.p) == 1:
                y = pow(y_sqr, (self.curve.p + 1) // 4, self.curve.p)
                return (x, y)
        raise ValueError("Can't generate point for block!")

    def decode_point_to_block(self, point):
        x, _ = point
        m = x // 10000
        data_len = (m.bit_length() + 7) // 8
        data = m.to_bytes(data_len, 'big')
        if data[0] > len(data) - 1:
            data = b'\x00' * (data[0] - (len(data) - 1)) + data
        length = data[0]
        return data[1:1 + length]

    def encrypt_block(self, block: bytes, public_key: tuple):
        M_point = self.encode_block_to_point(block)
        r = random.randrange(1, self.curve.q)
        C1 = self.curve.point_mul(r, self.curve.P)
        temp = self.curve.point_mul(r, public_key)
        C2 = self.curve.point_add(M_point, temp)
        return C1, C2

    def decrypt_block(self, ciphertext, private_key):
        C1, C2 = ciphertext
        temp = self.curve.point_mul(private_key, C1)
        neg_temp = self.curve.point_neg(temp)
        M_point = self.curve.point_add(C2, neg_temp)
        return self.decode_point_to_block(M_point)

    def encrypt(self, message: str, public_key: tuple, block_size=16):
        msg_bytes = message.encode('utf-8')
        ciphertext = []
        for i in range(0, len(msg_bytes), block_size):
            block = msg_bytes[i:i + block_size]
            ciphertext.append(self.encrypt_block(block, public_key))
        return ciphertext

    def decrypt(self, ciphertext, private_key):
        msg_bytes = b''
        for C1, C2 in ciphertext:
            msg_bytes += self.decrypt_block((C1, C2), private_key)
        return msg_bytes.decode('utf-8')
