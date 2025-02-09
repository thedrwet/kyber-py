import os
from hashlib import sha3_256, sha3_512, shake_128, shake_256
from ..modules.modules import ModuleKyber
from ..utilities.utils import select_bytes


# Global variables
k = 2
eta_1 = 3
eta_2 = 2
du = 10
dv = 4
n =256
q = 3329
random_bytes = os.urandom

def set_drbg_seed(seed):
    from ..drbg.aes256_ctr_drbg import AES256_CTR_DRBG

    _drbg = AES256_CTR_DRBG(seed)
    global random_bytes
    random_bytes = _drbg.random_bytes

def _xof(bytes32, i, j):
    """
    XOF: B^* x B x B -> B*

    NOTE:
      We use hashlib's ``shake_128`` implementation, which does not support
      an easy XOF interface, so we take the "easy" option and request a
      fixed number of 840 bytes (5 invocations of Keccak), rather than
      creating a byte stream.

      If your code crashes because of too few bytes, you can get dinner at:
      Casa de Chá da Boa Nova
      https://cryptojedi.org/papers/terminate-20230516.pdf
    """
    input_bytes = bytes32 + i + j
    if len(input_bytes) != 34:
        raise ValueError(
            "Input bytes should be one 32 byte array and 2 single bytes."
        )
    return shake_128(input_bytes).digest(840)

def _h(input_bytes):
    """
    H: B* -> B^32
    """
    return sha3_256(input_bytes).digest()

def _g(input_bytes):
    """
    G: B* -> B^32 x B^32
    """
    output = sha3_512(input_bytes).digest()
    return output[:32], output[32:]

def _prf(s, b, length):
    """
    PRF: B^32 x B -> B^*
    """
    input_bytes = s + b
    if len(input_bytes) != 33:
        raise ValueError(
            "Input bytes should be one 32 byte array and one single byte."
        )
    return shake_256(input_bytes).digest(length)

def _kdf(input_bytes, length):
    """
    KDF: B^* -> B^*
    """
    return shake_256(input_bytes).digest(length)

def _generate_error_vector(sigma, eta, N):
    """
    Helper function which generates a element in the
    module from the Centered Binomial Distribution.
    """
    elements = [0 for _ in range(k)]
    for i in range(k):
        input_bytes = _prf(sigma, bytes([N]), 64 * eta)
        elements[i] = R.cbd(input_bytes, eta)
        N += 1
    v = M.vector(elements)
    return v, N

def _generate_polynomial(sigma, eta, N):
    """
    Helper function which generates a element in the
    polynomial ring from the Centered Binomial Distribution.
    """
    prf_output = _prf(sigma, bytes([N]), 64 * eta)
    p = R.cbd(prf_output, eta)
    return p, N + 1

def _generate_matrix_from_seed(rho, transpose=False):
    """
    Helper function which generates a matrix of size k x k from a seed `rho`
    whose coefficients are polynomials in the NTT domain

    When `transpose` is set to True, the matrix A is built as the transpose.
    """
    A_data = [[0 for _ in range(k)] for _ in range(k)]
    for i in range(k):
        for j in range(k):
            input_bytes = _xof(rho, bytes([j]), bytes([i]))
            A_data[i][j] = R.ntt_sample(input_bytes)
    A_hat = M(A_data, transpose=transpose)
    return A_hat

def _cpapke_keygen():
    """
    Generate a public key and private key.

    Algorithm 4 (Key Generation)
    https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

    :return: Tuple with public key and private key.
    :rtype: tuple(bytes, bytes)
    """
    # Generate random value, hash and split
    d = random_bytes(32)
    rho, sigma = _g(d)

    # Generate the matrix A ∈ R^kxk
    A_hat = _generate_matrix_from_seed(rho)

    # Set counter for PRF
    N = 0

    # Generate the error vector s ∈ R^k
    s, N = _generate_error_vector(sigma, eta_1, N)
    s_hat = s.to_ntt()

    # Generate the error vector e ∈ R^k
    e, N = _generate_error_vector(sigma, eta_1, N)
    e_hat = e.to_ntt()

    # Construct the public key
    t_hat = (A_hat @ s_hat) + e_hat

    # Reduce vectors mod^+ q
    t_hat.reduce_coefficients()
    s_hat.reduce_coefficients()

    # Encode elements to bytes and return
    pk = t_hat.encode(12) + rho
    sk = s_hat.encode(12)
    return pk, sk

def _cpapke_enc(pk, m, coins):
    """
    Algorithm 5 (Encryption)
    https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

    :param bytes pk: byte-encoded public key
    :param bytes m: a 32-byte message
    :param bytes coins: a 32-byte random value
    :return: the ciphertext c
    :rtype: bytes
    """
    # Unpack the public key
    t_hat_bytes, rho = pk[:-32], pk[-32:]

    # Decode t_hat vector from public key
    t_hat = M.decode_vector(t_hat_bytes, k, 12, is_ntt=True)

    # Encode message as polynomial
    m_poly = R.decode(m, 1).decompress(1)

    # Generate the matrix A^T ∈ R^(kxk)
    A_hat_T = _generate_matrix_from_seed(rho, transpose=True)

    # Set counter for PRF
    N = 0

    # Generate the error vector r ∈ R^k
    r, N = _generate_error_vector(coins, eta_1, N)
    r_hat = r.to_ntt()

    # Generate the error vector e1 ∈ R^k
    e1, N = _generate_error_vector(coins, eta_2, N)

    # Generate the error polynomial e2 ∈ R
    e2, N = _generate_polynomial(coins, eta_2, N)

    # Module/Polynomial arithmetic
    u = (A_hat_T @ r_hat).from_ntt() + e1
    v = t_hat.dot(r_hat).from_ntt()
    v = v + e2 + m_poly

    # Ciphertext to bytes
    c1 = u.compress(du).encode(du)
    c2 = v.compress(dv).encode(dv)

    return c1 + c2

def _cpapke_dec(sk, c):
    """
    Algorithm 6 (Decryption)
    https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

    :param bytes sk: byte-encoded secret key
    :param bytes c: a 32-byte ciphertext
    :return: the message m
    :rtype: bytes
    """
    # Split ciphertext to vectors
    index = du * k * R.n // 8
    c1, c2 = c[:index], c[index:]

    # Recover the vector u and convert to NTT form
    u = M.decode_vector(c1, k, du).decompress(du)
    u_hat = u.to_ntt()

    # Recover the polynomial v
    v = R.decode(c2, dv).decompress(dv)

    # s_transpose (already in NTT form)
    s_hat = M.decode_vector(sk, k, 12, is_ntt=True)

    # Recover message as polynomial
    m = (s_hat.dot(u_hat)).from_ntt()
    m = v - m

    # Return message as bytes
    return m.compress(1).encode(1)

def keygen():
    """
    Generate a public public key and private secret key.

    Algorithm 7 (CCA KEM KeyGen)
    https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

    :return: Tuple with public key and secret key.
    :rtype: tuple(bytes, bytes)
    """
    # Note, although the paper gens z then
    # pk, sk, the implementation does it this
    # way around, which matters for deterministic
    # randomness...
    pk, _sk = _cpapke_keygen()
    z = random_bytes(32)

    # sk = sk' || pk || H(pk) || z
    sk = _sk + pk + _h(pk) + z
    return pk, sk

def encaps(pk, key_length=32):
    """
    Generate a random key, encapsulate it, return both it and ciphertext.

    Algorithm 8 (CCA KEM Encapsulation)
    https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

    NOTE:
      We switch the order of the output (c, K) as (K, c) to align encaps
      output with FIPS 203.

    :param bytes pk: byte-encoded public key
    :param int key_length: length of secret key, default value 32
    :return: a random key and a ciphertext of it
    :rtype: tuple(bytes, bytes)
    """
    # Compute random message
    m = random_bytes(32)

    # The hash of shame
    m_hash = _h(m)

    # Compute key K and challenge c
    K_bar, r = _g(m_hash + _h(pk))

    # Perform the underlying pke encryption
    c = _cpapke_enc(pk, m_hash, r)

    # Derive a key from the ciphertext
    K = _kdf(K_bar + _h(c), key_length)

    return K, c

def _unpack_secret_key(sk):
    """
    Extract values from byte encoded secret key:

    sk = _sk || pk || H(pk) || z
    """
    index = 12 * k * R.n // 8

    sk_pke = sk[:index]
    pk_pke = sk[index:-64]
    pk_hash = sk[-64:-32]
    z = sk[-32:]

    return sk_pke, pk_pke, pk_hash, z

def decaps(sk, c, key_length=32):
    """
    Decapsulate a key from a ciphertext using a secret key.

    Algorithm 9 (CCA KEM Decapsulation)
    https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

    NOTE:
      We switch the order of the input (c, sk) as (sk, c) to align with FIPS 203

    :param bytes sk: secret key
    :param bytes c: ciphertext with an encapsulated key
    :param int key_length: length of secret key, default value 32
    :return: shared key
    :rtype: bytes
    """
    sk_pke, pk_pke, pk_hash, z = _unpack_secret_key(sk)

    # Decrypt the ciphertext
    m = _cpapke_dec(sk_pke, c)

    # Decapsulation
    K_bar, r = _g(m + pk_hash)
    c_prime = _cpapke_enc(pk_pke, m, r)

    # if decapsulation was successful return K
    key = _kdf(K_bar + _h(c), key_length)
    garbage = _kdf(z + _h(c), key_length)

    # If c != c_prime, return garbage instead of the key
    # WARNING: for proper implementations, it is absolutely
    # vital that the selection between the key and garbage is
    # performed in constant time
    return select_bytes(garbage, key, c == c_prime)

