
from kyber import Kyber512, Kyber768, Kyber1024
pk, sk = Kyber512.keygen()
key, c = Kyber512.encaps(pk)
_key = Kyber512.decaps(sk, c)
assert key == _key
print("Kyber512 test passed")
print(pk)
print(sk)
