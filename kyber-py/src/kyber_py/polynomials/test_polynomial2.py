import polynomials_generic
import polynomials
from polynomials_generic import PolynomialRing
from polynomials import PolynomialRing as PolynomialRing2

R = PolynomialRing2(11, 8)
f = R.random_element()
f
f.compress(1)
f.decompress(1)
