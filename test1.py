import hashlib
from kyber import Kyber512, Kyber768, Kyber1024
def sha1_hash(data):
    return hashlib.sha1(data).hexdigest()
def test_kyber512(name):
    pk, sk = Kyber768.keygen()
    c, key = Kyber768.enc(pk)
    _key = Kyber768.dec(c, sk)
    assert key == _key
    print(f"{name} test passed!")
    print(f"Public Key: {pk}\n Secret Key")
    print(f"Secret Key: {sk}\n Ciphertext")
    print(f"Ciphertext: {c}\n Shared Key")
    print(f"Shared Key: {key}\n")
    print("-" * 80)
    print(f"SHA-1 of Public Key: {sha1_hash(pk)}\n SHA-1 of Secret Key")
    print(f"SHA-1 of Secret Key: {sha1_hash(sk)}\n SHA-1 of Ciphertext")
    print(f"SHA-1 of Ciphertext: {sha1_hash(c)}\n SHA-1 of Shared Key")
    print(f"SHA-1 of Shared Key: {sha1_hash(key)}\n")
    print("-" * 80)


if __name__ == "__main__":
    test_kyber512("Kyber768")