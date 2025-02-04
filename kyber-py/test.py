from kyber import Kyber512, Kyber768, Kyber1024

def test_kyber512(name):
    pk, sk = Kyber512.keygen()
    c, key = Kyber512.enc(pk)
    _key = Kyber512.dec(c, sk)
    assert key == _key
    print(f"{name} test passed!\n \n \n")
    print(f"Public Key: {pk}\n \n")
    print(f"Secret Key: {sk}\n \n")
    print(f"Ciphertext: {c} \n \n")
    print(f"Shared Key: {key}\n \n")
    print("-" * 80)

if __name__ == "__main__":
    test_kyber512("Kyber512")
    