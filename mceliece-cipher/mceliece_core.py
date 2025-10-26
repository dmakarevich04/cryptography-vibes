import os
import math
import random
import itertools
import pickle
from typing import Tuple, List
import numpy as np


def bytes_from_bits(bits: List[int]) -> bytes:
    bits = np.array(bits, dtype=np.uint8)
    extra = (-len(bits)) % 8
    if extra:
        bits = np.concatenate([bits, np.zeros(extra, dtype=np.uint8)])
    return np.packbits(bits).tobytes()


def gaussian_elimination(A: List[List[int]]) -> Tuple[List[List[int]], List[int]]:
    A = [row[:] for row in A]
    rows = len(A)
    cols = len(A[0]) if rows > 0 else 0
    r = 0
    pivot_cols = []
    for c in range(cols):
        if r >= rows:
            break
        sel = None
        for i in range(r, rows):
            if A[i][c] == 1:
                sel = i
                break
        if sel is None:
            continue
        if sel != r:
            A[r], A[sel] = A[sel], A[r]
        pivot_cols.append(c)
        for i in range(rows):
            if i != r and A[i][c] == 1:
                A[i] = [(x ^ y) for x, y in zip(A[i], A[r])]
        r += 1
    return A, pivot_cols


def rank(A: List[List[int]]) -> int:
    B, piv = gaussian_elimination(A)
    return len(piv)


def invert_matrix_gauss(A: List[List[int]]) -> List[List[int]]:
    A = np.array(A, dtype=np.uint8)
    n = A.shape[0]
    M = A.copy()
    Inv = np.eye(n, dtype=np.uint8)
    for col in range(n):
        piv = np.where(M[col:, col] == 1)[0]
        piv = piv[0] + col
        if piv != col:
            M[[col, piv]] = M[[piv, col]]
            Inv[[col, piv]] = Inv[[piv, col]]
        for r in range(n):
            if r != col and M[r, col]:
                M[r] ^= M[col]
                Inv[r] ^= Inv[col]
    return Inv.tolist()


def nullspace_basis(G: List[List[int]]) -> List[List[int]]:
    k = len(G)
    if k == 0:
        return []
    n = len(G[0])
    G_copy = [row[:] for row in G]
    E, piv = gaussian_elimination(G_copy)
    piv_set = set(piv)
    free_cols = [j for j in range(n) if j not in piv_set]
    basis = []
    for fc in free_cols:
        x = [0] * n
        x[fc] = 1
        for r_idx, pcol in enumerate(piv):
            s = 0
            for j in range(n):
                if j == pcol:
                    continue
                s ^= (E[r_idx][j] & x[j])
            x[pcol] = s
        basis.append(x)
    return basis


def build_syndrome_table(H: List[List[int]], n: int, t: int):
    synd_table = {}
    positions = list(range(n))
    for err_num in range(0, t+1):
        for comb in itertools.combinations(positions, err_num):
            e = [0]*n
            for pos in comb:
                e[pos] = 1
            syn = tuple((np.dot(H, e) % 2).astype(int).tolist())
            if syn not in synd_table:
                synd_table[syn] = e
    return synd_table


def random_full_rank_matrix(k, n):
    while True:
        M = [[random.getrandbits(1) for _ in range(n)] for __ in range(k)]
        if rank(M) == k:
            return M


def random_permutation_matrix(n):
    perm = np.random.permutation(n)
    P = np.eye(n, dtype=int)[perm].tolist()
    return P, perm.tolist()


def permutation_inverse(perm):
    inv = [0]*len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def matrix_from_perm(perm):
    return np.eye(len(perm), dtype=int)[perm].tolist()


def generate_keypair(n: int, k: int, t: int):
    G = random_full_rank_matrix(k, n)  # порождающая матрица G 
    S = random_full_rank_matrix(k, k)  # двоичная невырожденная матрица S
    S_inv = invert_matrix_gauss(S)  
    P, perm = random_permutation_matrix(n)  # подстановочная матрица P
    P_inv_perm = permutation_inverse(perm)
    P_inv = matrix_from_perm(P_inv_perm)
    SG = (np.dot(S, G) % 2).astype(int).tolist()
    G_pub = (np.dot(SG, P) % 2).astype(int).tolist()
    H_rows = nullspace_basis(G)  # H⋅GT=0
    synd_table = build_syndrome_table(H_rows, n, t)
    key_public = {'n': n, 'k': k, 't': t, 'G_pub': G_pub}
    key_private = {'n': n, 'k': k, 't': t, 'G': G, 'S': S, 'S_inv': S_inv,
                   'P': P, 'P_inv': P_inv, 'perm': perm, 'synd_table': synd_table,
                   'H_rows': H_rows}
    return key_public, key_private


def pad_bits(bits: List[int], block_size: int) -> Tuple[List[int], int]:
    L = len(bits)
    pad = (-L) % block_size
    padded = bits + [0]*pad
    return padded, pad


def encode_block(m_bits: List[int], G_pub: List[List[int]]) -> List[int]:
    return (np.dot(m_bits, G_pub) % 2).astype(int).tolist()


def decode_block(c_bits: List[int], priv: dict) -> List[int]:
    P_inv = priv['P_inv']
    synd_table = priv['synd_table']
    G = priv['G']
    S_inv = priv['S_inv']
    k = priv['k']
    c1 = (np.dot(c_bits, P_inv) % 2).astype(int).tolist() #возвращаем ошибки на те же места
    H_rows = priv['H_rows']
    s = tuple((np.dot(H_rows, c1) % 2).astype(int).tolist())  # s=H⋅c1T
    if s not in synd_table:
        raise ValueError("Синдром не найден")
    e = synd_table[s]
    u = (np.bitwise_xor(c1, e)).tolist()  # u = c1 xor e
    # G ^ T · α ^ T = u ^ T,
    M = np.transpose(G).tolist()
    M_work = [row[:] for row in M] 
    u_work = u[:]
    n_rows = len(M_work)
    n_cols = k
    row = 0
    pivot_for_col = {}
    for col in range(n_cols):
        sel = None
        for r in range(row, n_rows):
            if M_work[r][col] == 1:
                sel = r
                break
        if sel is None:
            continue
        if sel != row:
            M_work[row], M_work[sel] = M_work[sel], M_work[row]
            u_work[row], u_work[sel] = u_work[sel], u_work[row]
        for r in range(n_rows):
            if r != row and M_work[r][col] == 1:
                M_work[r] = [(x ^ y) for x, y in zip(M_work[r], M_work[row])]
                u_work[r] ^= u_work[row]
        pivot_for_col[col] = row
        row += 1
        if row >= n_rows:
            break
    alpha = [0]*k
    for col, r in pivot_for_col.items():
        alpha[col] = u_work[r]
    m1 = alpha  # m1 * G = u
    m = (np.dot(m1, S_inv) % 2).astype(int).tolist()
    return m


def encrypt_bytes(data: bytes, pubkey: dict) -> bytes:
    n = pubkey['n']
    k = pubkey['k']
    G_pub = pubkey['G_pub']
    t = pubkey['t']
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8)).tolist()
    bits_padded, pad = pad_bits(bits, k)
    out_bits = []
    for i in range(0, len(bits_padded), k):
        m = bits_padded[i:i+k]
        err_num = random.randint(0, t)
        pos = random.sample(range(n), err_num)
        e = [0]*n
        for p in pos:
            e[p] = 1
        c = encode_block(m, G_pub)
        c = (np.bitwise_xor(c, e)).tolist()
        out_bits.extend(c)
    header = bytes([pad])
    return header + bytes_from_bits(out_bits)


def decrypt_bytes(ciphertext: bytes, privkey: dict) -> bytes:
    n = privkey['n']
    if len(ciphertext) == 0:
        return b''
    pad = ciphertext[0]
    bits = np.unpackbits(np.frombuffer(ciphertext[1:], dtype=np.uint8)).tolist()
    bits = bits[: (len(bits)//n)*n]
    out_bits = []
    for i in range(0, len(bits), n):
        c = bits[i:i+n]
        m = decode_block(c, privkey)
        out_bits.extend(m)
    if pad:
        out_bits = out_bits[:-pad]
    return bytes_from_bits(out_bits)


def save_key_public(pubkey, filename):
    with open(filename, 'wb') as f:
        pickle.dump(pubkey, f)


def save_key_private(privkey, filename):
    with open(filename, 'wb') as f:
        pickle.dump(privkey, f)


def load_key(filename):
    with open(filename, 'rb') as f:
        return pickle.load(f)
