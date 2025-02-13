
import logging
from kyber_py.kyber import Kyber512

# Set up logging
logging.basicConfig(level=logging.INFO)

pk, sk = Kyber512.keygen()
logging.info(f"Generated keys: pk={pk.hex()}, sk={sk.hex()}")
key, c = Kyber512.encaps(pk)
logging.info(f"Encapsulated key: key={key.hex()}, c={c.hex()}")

_key = Kyber512.decaps(sk, c)
logging.info(f"Decapsulated key: _key={_key.hex()}")

assert key == _key
print("Kyber512 test passed")
logging.info("Test passed successfully.")

#a="hello how are you iam fi"
a=b'7\x1fb\xd1\rqu\xaa\xfe\xca $\xf2\x02U\x99M\x90\xd4\x08\xde+7\x15\xf0:7\r\xae\x83j%'
#a=a.encode("utf-8")
print(a)
print(a.__sizeof__())
