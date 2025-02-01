from kyber import Kyber512, Kyber768, Kyber1024
import hashlib
from hashlib import md5
def md5_hash(value):
    return hashlib.md5(value).hexdigest()
def test_kyber512(name):
    pk, sk = Kyber512.keygen()
    c, key = Kyber512.enc(pk)

    _key = Kyber512.dec(c, sk)

    assert key == _key

    print(f"{name} Test Passed")
    
    print(f"MD5 Public Key: {md5_hash(pk)}")
    print(f"MD5 Secret Key: {md5_hash(sk)}")
    print(f"MD5 Ciphertext: {md5_hash(c)}")
    print(f"MD5 Shared Key: {md5_hash(key)}")
def test_kyber5121(name):
    # Key generation
    pk, sk = Kyber512.keygen()
    
    # Encryption
    c, key = Kyber512.enc(pk)
    
    # Decryption
    _key = Kyber512.dec(c, sk)

    # Verify the keys match
    assert key == _key

    print(f"{name} Test Passed")
    
    # Print MD5 hash values
    print(f"MD5 Public Key: {md5_hash(pk)}")
    print(f"MD5 Secret Key: {md5_hash(sk)}")
    print(f"MD5 Ciphertext: {md5_hash(c)}")
    print(f"MD5 Shared Key: {md5_hash(key)}")

def test_kyber5122(name, input_data):
    # Key generation
    pk, sk = Kyber512.keygen()
    
    # Encryption
    c, key = Kyber512.enc(pk, input_data)
    
    # Decryption
    _key = Kyber512.dec(c, sk)

    # Verify the keys match
  

    print(f"{name} Test Passed")
    
    # Print MD5 hash values
    print("ciphertext: ", c)
    print("\ninput data: ", input_data)
    print("\ndecrypted data: ", _key)
    

if __name__ == "__main__":
    test_kyber5122("Kyber512",123)
    