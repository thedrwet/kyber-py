import random
import matplotlib.pyplot as plt
import kyber_py.polynomials.polynomials as poly #importing the polynomials module from the kyber_py package

# Generate a list of random floats
polynomial = poly.Polynomial(3, 5) #creating a polynomial object with degree 3 and modulus 5
print(polynomial) #printing the polynomial object


