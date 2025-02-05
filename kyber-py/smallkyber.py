import numpy as np


q=17


a= [2,3,10,3]
b= [3,0,14,10,4]
q=17


print (np.poly1d(a))
print (np.poly1d(b))

r1 = np.floor( np.polyadd(a,b)) % q
r2 = np.floor( np.polymul(a,b)) % q
r3 = np.floor( np.polysub(a,b)) % q
r4 = np.floor( np.polydiv(a,b)[1]) % q


print (np.poly1d(r1))
print (np.poly1d(r2))
print (np.poly1d(r3))
print (np.poly1d(r4))