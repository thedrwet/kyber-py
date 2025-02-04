import os
import sys
from kyber_py.ml_kem.ml_kem import ML_KEM

def main():
    # Initialize ML-KEM with example parameters
    params = {
        "k": 3,
        "eta_1": 2,
        "eta_2": 2,
        "du": 2,
        "dv": 2
    }
    ml_kem = ML_KEM(params)

    # Generate keys
    ek, dk = ml_kem.keygen()

    # Input message to encrypt
    message = input("Enter a message to encrypt: ").encode('utf-8')

    # Encrypt the message
    K, c = ml_kem.encaps(ek)

    # Decrypt the ciphertext
    K_prime = ml_kem.decaps(dk, c)

    # Output results
    print(f"Original Message: {message.decode('utf-8')}")
    print(f"Ciphertext: {c.hex()}")
    print(f"Decrypted Key: {K_prime.hex()}")

if __name__ == "__main__":
    main()
