R = PolynomialRing(11, 8)
x = R.gen()
f = 3*x**3 + 4*x**7
g = R.random_element()
f*g
f + f
g - g
