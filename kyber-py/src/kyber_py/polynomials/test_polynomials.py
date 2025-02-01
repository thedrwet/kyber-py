import polynomials_generic
from polynomials_generic import PolynomialRing
def main():
    R = PolynomialRing(11, 8)
    x = R.gen()
    f = 3 * x**3 + 4 * x**7
    g = R.random_element()
    print("Polynomial f:", f)
    print("Polynomial g:", g)
    print("f * g:", f * g)
    print("f + f:", f + f)
    print("g - g:", g - g)
    

if __name__ == "__main__":
    main()