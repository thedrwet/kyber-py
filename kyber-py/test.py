import hashlib
from hashlib import sha256
from kyber import Kyber512, Kyber768, Kyber1024 #, Kyber512, Kyber768, Kyber1024

def test_kyber512(name):
    pk, sk = Kyber512.keygen()
    c, key = Kyber512.enc(pk)
    _key = Kyber512.dec(c, sk)
    
    #assert key == _key
    #print(f"{name} test passed!\n \n \n")
    #print(f"Public Key: {pk.hex()}\n \n")
    #print(f"Secret Key: {sk.hex()}\n \n")
    #print(f"Ciphertext: {c.hex()} \n \n")
    #print(f"Shared Key: {key.hex()}\n \n")
    #print("helloworld\n\n\n"+_key.hex())
   # print("decrypted message:\n\n\n",)
    #print("-" * 80)
    #print("MD5 Public Key: ", hashlib.md5(pk).hexdigest())
    #print("MD5 Secret Key: ", hashlib.md5(sk).hexdigest())
    #print("MD5 Ciphertext: ", hashlib.md5(c).hexdigest())
    #print("MD5 Shared Key: ", hashlib.md5(key).hexdigest())
    #print("MD5 decrypted key: "), hashlib.md5(_key).hexdigest()
    #print("SHA256 Public Key: ", sha256(pk).hexdigest())
    #print("SHA256 Secret Key: ", sha256(sk).hexdigest())
    #print("SHA256 Ciphertext: ", sha256(c).hexdigest())
    #print("SHA256 Shared Key: ", sha256(key).hexdigest())



if __name__ == "__main__":
    test_kyber512("Kyber512")
    