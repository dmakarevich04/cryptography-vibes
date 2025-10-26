import random

def generate_key(bits=42): #p=4k+3; q=4k+3 и p ≠q
    def is_simple(n):
        if n <= 1:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    def generate_simple(bits):
        while True:
            num = random.getrandbits(bits)
            if num % 4 == 3 and is_simple(num):
                return num

    p = generate_simple(bits)
    q = generate_simple(bits)
    open_key = p * q
    close_key = (p, q)
    return open_key, close_key


def extended_gcd(a, b): 
    if a == 0:
        return (0, 1)
    else:
        x, y = extended_gcd(b % a, a)
        return (y - (b // a) * x, x)


def find_Yp_Yq(p, q):
    x, y = extended_gcd(p, q) #x*p + y*q = 1
    if x < 0:
        x += q
    Yp = x
    Yq = (1 - Yp * p) // q
    return Yp, Yq


def mod(k, b, m):
    i = 0
    a = 1
    v = []
    while k > 0:
        v.append(k % 2)
        k = (k - v[i]) // 2
        i += 1
    for j in range(i):
        if v[j] == 1:
            a = (a * b) % m
            b = (b * b) % m
        else:
            b = (b * b) % m
    return a


def encrypted(text, open_key): # number² mod n 
    number = ord(text)
    c = (number ** 2) % open_key
    return c


def decrypted(c, open_key, close_key):
    p, q = close_key
    x, y = find_Yp_Yq(*close_key)
    while x * p + y * q != 1:
        x, y = find_Yp_Yq(*close_key)

    r = mod((p + 1) // 4, c, p)
    s = mod((q + 1) // 4, c, q)

    #m² ≡ c (mod p)
    #m² ≡ c (mod q)

    r1 = (x * p * s + y * q * r) % open_key
    r2 = (open_key - r1)
    r3 = (x * p * s - y * q * r) % open_key
    r4 = (open_key - r3)

    for item in (r1, r2, r3, r4):
        if item <= 1200:
            return chr(item)


def encrypt_text(text, open_key):
    return " ".join(str(encrypted(ch, open_key)) for ch in text)


def decrypt_text(numbers_str, open_key, close_key):
    decrypted_result = ""
    for num in numbers_str.split():
        try:
            decrypted_result += decrypted(int(num), open_key, close_key) or "?"
        except Exception:
            decrypted_result += "?"
    return decrypted_result
