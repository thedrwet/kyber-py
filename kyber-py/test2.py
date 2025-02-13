import logging
from kyber_py.ml_kem import ML_KEM_512

# Set up logging
logging.basicConfig(level=logging.INFO)

ek, dk = ML_KEM_512.keygen()
logging.info(f"Generated keys: ek={ek.hex()}, dk={dk.hex()}")

logging.info(f"Generated keys: ek={ek.hex()}, dk={dk.hex()}")

key, ct = ML_KEM_512.encaps(ek)
logging.info(f"Encapsulated key: key={key.hex()}, ct={ct.hex()}")

_key = ML_KEM_512.decaps(dk, ct)
logging.info(f"Decapsulated key: _key={_key.hex()}")

assert key == _key
print("Test passed")
logging.info("Test passed successfully.")
