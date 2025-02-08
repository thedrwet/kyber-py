import os
import random
from hashlib import sha3_256, sha3_512, shake_128, shake_256
from .polynomials import *
from .modules import *
from .ntt_helper import NTTHelperKyber
from .aes256_ctr_drbg import AES256_CTR_DRBG

try:
except ImportError as e:
    print("Error importing AES CTR DRBG. Have you tried installing requirements?")
    print(f"ImportError: {e}\n")
    print("Kyber will work perfectly fine with system randomness")

DEFAULT_PARAMETERS = {
    "kyber_512": {
        "n": 256,
        "k": 2,
        "q": 3329,
        "eta_1": 3,
        "eta_2": 2,
        "du": 10,
        "dv": 4,
    },
    "kyber_768": {
        "n": 256,
        "k": 3,
        "q": 3329,
        "eta_1": 2,
        "eta_2": 2,
        "du": 10,
        "dv": 4,
    },
    "kyber_1024": {
        "n": 256,
        "k": 4,
        "q": 3329,
        "eta_1": 2,
        "eta_2": 2,
        "du": 11,
        "dv": 5,
    }
}

def set_drbg_seed(drbg, seed):
    drbg = AES256_CTR_DRBG(seed)
    return drbg

def reseed_drbg(drbg, seed):
    if drbg is None:
        raise Warning("Cannot reseed DRBG without first initialising. Try using `set_drbg_seed`")
    else:
        drbg.reseed(seed)

def _xof(bytes32, a, b, length):
    input_bytes = bytes32 + a + b
    if len(input_bytes) != 34:
        raise ValueError("Input bytes should be one 32 byte array and 2 single bytes.")
    return shake_128(input_bytes).digest(length)

def _h(input_bytes):
    return sha3_256(input_bytes).digest()

def _g(input_bytes):
    output = sha3_512(input_bytes).digest()
    return output[:32], output[32:]

def _prf(s, b, length):
    input_bytes = s + b
    if len(input_bytes) != 33:
        raise ValueError("Input bytes should be one 32 byte array and one single byte.")
    return shake_256(input_bytes).digest(length)

def _kdf(input_bytes, length):
    return shake_256(input_bytes).digest(length)

def _generate_error_vector(R, M, sigma, eta, N, k, is_ntt=False):
    elements = []
    for i in range(k):
        input_bytes = _prf(sigma, bytes([N]), 64 * eta)
        poly = R.cbd(input_bytes, eta, is_ntt=is_ntt)
        elements.append(poly)
        N = N + 1
    v = M(elements).transpose()
    return v, N

def _generate_matrix_from_seed(R, M, rho, k, transpose=False, is_ntt=False):
    A = []
    for i in range(k):
        row = []
        for j in range(k):
            if transpose:
                input_bytes = _xof(rho, bytes([i]), bytes([j]), 3 * R.n)
            else:
                input_bytes = _xof(rho, bytes([j]), bytes([i]), 3 * R.n)
            aij = R.parse(input_bytes, is_ntt=is_ntt)
            row.append(aij)
        A.append(row)
    return M(A)

def _cpapke_keygen(R, M, random_bytes, k, eta_1):
    d = random_bytes(32)
    rho, sigma = _g(d)
    N = 0
    A = _generate_matrix_from_seed(R, M, rho, k, is_ntt=True)
    s, N = _generate_error_vector(R, M, sigma, eta_1, N, k)
    s.to_ntt()
    e, N = _generate_error_vector(R, M, sigma, eta_1, N, k)
    e.to_ntt()
    t = (A @ s).to_montgomery() + e
    t.reduce_coefficents()
    s.reduce_coefficents()
    pk = t.encode(l=12) + rho
    sk = s.encode(l=12)
    return pk, sk

def _cpapke_enc(R, M, pk, m, coins, k, eta_1, eta_2, du, dv):
    N = 0
    rho = pk[-32:]
    tt = M.decode(pk, 1, k, l=12, is_ntt=True)
    m_poly = R.decode(m, l=1).decompress(1)
    At = _generate_matrix_from_seed(R, M, rho, k, transpose=True, is_ntt=True)
    r, N = _generate_error_vector(R, M, coins, eta_1, N, k)
    r.to_ntt()
    e1, N = _generate_error_vector(R, M, coins, eta_2, N, k)
    input_bytes = _prf(coins, bytes([N]), 64 * eta_2)
    e2 = R.cbd(input_bytes, eta_2)
    u = (At @ r).from_ntt() + e1
    v = (tt @ r)[0][0].from_ntt()
    v = v + e2 + m_poly
    c1 = u.compress(du).encode(l=du)
    c2 = v.compress(dv).encode(l=dv)
    return c1 + c2

def _cpapke_dec(R, M, sk, c, k, du, dv):
    index = du * k * R.n // 8
    c2 = c[index:]
    u = M.decode(c, k, 1, l=du).decompress(du)
    u.to_ntt()
    v = R.decode(c2, l=dv).decompress(dv)
    st = M.decode(sk, 1, k, l=12, is_ntt=True)
    m = (st @ u)[0][0].from_ntt()
    m = v - m
    return m.compress(1).encode(1)

def keygen(R, M, random_bytes, k, eta_1):
    pk, _sk = _cpapke_keygen(R, M, random_bytes, k, eta_1)
    z = random_bytes(32)
    sk = _sk + pk + _h(pk) + z
    return pk, sk

def enc(R, M, pk, key_length, k, eta_1, eta_2, du, dv):
    m = input("enter the value").encode()
    m_hash = _h(m)
    Kbar, r = _g(m_hash + _h(pk))
    c = _cpapke_enc(R, M, pk, m_hash, r, k, eta_1, eta_2, du, dv)
    K = _kdf(Kbar + _h(c), key_length)
    return c, K

def dec(R, M, c, sk, key_length, k, du, dv):
    index = 12 * k * R.n // 8
    _sk = sk[:index]
    pk = sk[index:-64]
    hpk = sk[-64:-32]
    z = sk[-32:]
    _m = _cpapke_dec(R, M, _sk, c, k, du, dv)
    try:
        decrypted_message = _m.decode('utf-8')
    except UnicodeDecodeError:
        decrypted_message = _m.hex()
    print(f"Decrypted message: {decrypted_message}")
    _Kbar, _r = _g(_m + hpk)
    _c = _cpapke_enc(R, M, pk, _m, _r, k, eta_1, eta_2, du, dv)
    if c == _c:
        return _kdf(_Kbar + _h(c), key_length)
    return _kdf(z + _h(c), key_length)

# Initialise with default parameters for easy import
R = PolynomialRing(DEFAULT_PARAMETERS["kyber_512"]["q"], DEFAULT_PARAMETERS["kyber_512"]["n"], ntt_helper=NTTHelperKyber)
M = Module(R)
Kyber512 = {
    "R": R,
    "M": M,
    "params": DEFAULT_PARAMETERS["kyber_512"]
}

R = PolynomialRing(DEFAULT_PARAMETERS["kyber_768"]["q"], DEFAULT_PARAMETERS["kyber_768"]["n"], ntt_helper=NTTHelperKyber)
M = Module(R)
Kyber768 = {
    "R": R,
    "M": M,
    "params": DEFAULT_PARAMETERS["kyber_768"]
}

R = PolynomialRing(DEFAULT_PARAMETERS["kyber_1024"]["q"], DEFAULT_PARAMETERS["kyber_1024"]["n"], ntt_helper=NTTHelperKyber)
M = Module(R)
Kyber1024 = {
    "R": R,
    "M": M,
    "params": DEFAULT_PARAMETERS["kyber_1024"]
}