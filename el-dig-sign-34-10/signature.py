import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append("/home/darya/Documents/ISM/cryptography-vibes/hash_functions")

import random
from constants import p, q, x, y
from keypair import ECPoint
import hash_functions
from hash_functions import core_streebog

def gost_hash(message):
    return core_streebog.streebog_256(message)


class ECSignature:
    @staticmethod
    def generate_signature(message, private_key):
        alpha = int.from_bytes(gost_hash(message), byteorder='big')
        e = alpha % q

        if e == 0:
            e = 1
        while True:
            k = random.randrange(1, q)
            P = ECPoint(x, y)
            C = P.mul(k)
            r = C.x % q
            if r == 0:
                continue
            s = (r * private_key + k * e) % q
            if s != 0:
                break
        return (r, s)

    @staticmethod
    def verify_signature(message, signature, public_key):
        r, s = signature
        if not (1 <= r < q and 1 <= s < q):
            return False
        alpha = int.from_bytes(gost_hash(message), byteorder='big')
        e = alpha % q
        if e == 0:
            e = 1
        v = pow(e, -1, q)
        z1 = (s * v) % q
        z2 = (-r * v) % q
        P = ECPoint(x, y)
        R = P.mul(z1) + public_key.mul(z2)
        if R.x % q == r:
            return True
        return False


def sign_file(file_path, key_pair):
    with open(file_path, 'rb') as f:
        file_data = f.read()
    signature = ECSignature.generate_signature(file_data, key_pair.d)
    return signature


def verify_file(file_path, signature, key_pair):
    with open(file_path, 'rb') as f:
        file_data = f.read()
    is_valid = ECSignature.verify_signature(file_data, signature, key_pair.Q)
    return is_valid
