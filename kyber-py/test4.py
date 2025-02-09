import kyber
import kyber.modules

# Generate a key pair
public_key, secret_key = kyber.Kyber512._cpapke_keygen()
#print("Public key:", public_key.hex())
#print("Secret key:\n\n", secret_key.hex())


d = kyber.Kyber512._keypair()
rho, sigma = kyber.Kyber512._g(d)
print("rho:", rho.hex())
print("sigma:", sigma.hex())
# Encrypt a message using the public key
#ciphertext, shared_secret_enc = kyber.encrypt(public_key)

# Decrypt the ciphertext using the secret key
#shared_secret_dec = kyber.decrypt(ciphertext, secret_key)

# Verify that the shared secrets match
#assert shared_secret_enc == shared_secret_dec
#print("Encryption and decryption were successful!")