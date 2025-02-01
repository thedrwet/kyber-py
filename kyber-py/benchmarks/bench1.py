import cProfile
from kyber_py.kyber import Kyber512, Kyber768, Kyber1024

def profile_kyber(Kyber):
    pk, sk = Kyber.keygen()
    key, c = Kyber.encaps(pk)

    gvars = {}
    lvars = {"Kyber": Kyber, "c": c, "pk": pk, "sk": sk}

    cProfile.runctx(
        "[Kyber.keygen() for _ in range(100)]",
        globals=gvars,
        locals=lvars,
        sort=1,
    )
    cProfile.runctx(
        "[Kyber.encaps(pk) for _ in range(100)]",
        globals=gvars,
        locals=lvars,
        sort=1,
    )
    cProfile.runctx(
        "[Kyber.decaps(sk, c) for _ in range(100)]",
        globals=gvars,
        locals=lvars,
        sort=1,
    )

if __name__ == "__main__":
    count = 1000
    print("-" * 80)
    print(
        "   Params    |  keygen  |  keygen/s  |  encap  |  encap/s  "
        "|  decap  |  decap/s"
    )
    print("-" * 80)

    profile_kyber(Kyber512)
    profile_kyber(Kyber768)
    profile_kyber(Kyber1024)