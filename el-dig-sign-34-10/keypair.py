from constants import p, q, a, b, x, y
import random

class ECPoint:

    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __add__(self, other):
        if self.x is None and self.y is None:
            return other
        if other.x is None and other.y is None:
            return self
        if self == other:
            return self.double()
        if self.x == other.x:
            return ECPoint(None, None)  # Точка на бесконечности
        l = ((other.y - self.y) * pow(other.x - self.x, -1, p)) % p
        x3 = (l * l - self.x - other.x) % p
        y3 = (l * (self.x - x3) - self.y) % p
        return ECPoint(x3, y3)
    
    def double(self):
        if self.y == 0:
            return ECPoint(None, None)
        l = ((3 * self.x * self.x + a) * pow(2 * self.y, -1, p)) % p
        x3 = (l * l - 2 * self.x) % p
        y3 = (l * (self.x - x3) - self.y) % p
        return ECPoint(x3, y3)
    
    def mul(self, k):
        k = k % q
        result = ECPoint(None, None)
        addend = self

        while k:
            if k & 1:
                result = result + addend
            addend = addend.double()
            k >>= 1

        return result


class ECKeyPair:
    def __init__(self):
        self.k = random.randrange(1, q)
        G = ECPoint(x, y)
        self.Q = G.mul(self.k)


def generate_keys():
    return ECKeyPair()
