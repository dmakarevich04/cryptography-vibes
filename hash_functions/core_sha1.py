import struct

def left_rotate(w, n):
    return ((w << n) | (w >> (32 - n))) & 0xffffffff


def process_block(block, A, B, C, D, E):
    w = [0] * 80
    for i in range(16):
        w[i] = struct.unpack('>I', block[i*4:i*4+4])[0]

    for i in range(16, 80):
        w[i] = left_rotate(w[i-16] ^ w[i-14] ^ w[i-8] ^ w[i-3], 1)
    
    a, b, c, d, e = A, B, C, D, E

    for i in range(80):
        if i < 20:
            k = 0x5A827999
            f = d ^ (b & (c ^ d))
        elif i < 40:
            k = 0x6ED9EBA1
            f = b ^ c ^ d
        elif i < 60:
            k = 0x8F1BBCDC
            f = (b & c) | (b & d) | (c & d)
        else:
            k = 0xCA62C1D6
            f = b ^ c ^ d

        a, b, c, d, e = ((left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, a, left_rotate(b, 30), c, d)

    A = (A + a) & 0xffffffff
    B = (B + b) & 0xffffffff
    C = (C + c) & 0xffffffff
    D = (D + d) & 0xffffffff
    E = (E + e) & 0xffffffff

    return A, B, C, D, E

def sha1_hash(data: bytes):

    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476
    E = 0xC3D2E1F0
    
    original_bit_len = len(data) * 8

    original_len = len(data)

    data += b'\x80'
    padding = (56 - (original_len + 1) % 64) % 64
    data += b'\x00' * padding
    data += struct.pack('>Q', original_bit_len)

    for i in range(0, len(data), 64):
        block = data[i:i+64]
        if len(block) < 64:
            raise ValueError("Padding error: chunk too short")
        A, B, C, D, E = process_block(block, A, B, C, D, E)
    
    return '%08x%08x%08x%08x%08x' % (A, B, C, D, E)

        
