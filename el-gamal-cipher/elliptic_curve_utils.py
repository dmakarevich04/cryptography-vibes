class EllipticCurve:
    def __init__(self, a, b, p, q, x, y):
        self.a = a
        self.b = b
        self.p = p
        self.q = q
        self.P = (x, y)

    def point_add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q

        if x1 == x2:
            if y1 == y2:
                if y1 == 0:
                    return None
                s = (3 * x1 * x1 + self.a) * pow(2 * y1, self.p - 2, self.p) % self.p
            else:
                return None
        else:
            s = (y2 - y1) * pow(x2 - x1, self.p - 2, self.p) % self.p
        x3 = (s * s - x1 - x2) % self.p
        y3 = (s * (x1 - x3) - y1) % self.p

        return (x3, y3)
    
    def point_mul(self, k, point):
        result = None
        addend = point
        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return result
    
    def point_neg(self, point):
        x, y = point
        return (x, (-y) % self.p)
