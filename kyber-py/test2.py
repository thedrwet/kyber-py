import random
from kyber_py.ml_kem import ML_KEM_512

ek, dk = ML_KEM_512.keygen()
key, ct = ML_KEM_512.encaps(ek)
_key = ML_KEM_512.decaps(dk, ct)
assert key == _key
#print("ML_KEM_512 test passed!")
#print(f"Public Key: {ek.hex()}")
#print(f"Secret Key: {dk.hex()}")
#print(f"Ciphertext: {ct.hex()}")
#print(f"Shared Key: {key.hex()}")
a=b'7\x1fb\xd1\rqu\xaa\xfe\xca $\xf2\x02U\x99M\x90\xd4\x08\xde+7\x15\xf0:7\r\xae\x83j%'
print(a.hex())

