import sys

# Add the path to the kyber_py module
sys.path.append('D:/kyber githubme/kyber-py/kyber-py/src')


from .ml_kem import ML_KEM

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
    pk, sk = ml_kem.keygen()

    # Input message to encrypt
    message = input("Enter a message to encrypt: ").encode('utf-8')

    # Encrypt the message
    ciphertext, shared_key_enc = ml_kem.enc(pk, message)
    print("Ciphertext:", ciphertext)
    print("Shared Key (Encryption):", shared_key_enc)

    # Decrypt the message
    shared_key_dec = ml_kem.dec(sk, ciphertext)
    print("Shared Key (Decryption):", shared_key_dec)

    # Verify the keys match
    assert shared_key_enc == shared_key_dec, "Decryption failed: keys do not match"
    print("Decryption successful: keys match")

if __name__ == "__main__":
    main()