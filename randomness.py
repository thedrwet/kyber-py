import random
import matplotlib.pyplot as plt
import kyber_py.polynomials.polynomials as poly  # importing the polynomials module from the kyber_py package
import os

# Generate a list of random floats
# creating a polynomial object with degree 3 and modulus 5
# printing the polynomial object
i = os.urandom(3)
a=[]
a.append(i[:16])
a.append(i[16:32])
print(a)
# Create an instance of the PolynomialRingKyber class
poly_instance = poly.PolynomialRingKyber()

# Call the ntt_sample method with the required input_bytes argument
a = poly_instance.ntt_sample(input_bytes=i)

