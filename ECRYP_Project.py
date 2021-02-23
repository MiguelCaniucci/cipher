##############################
# ECRYP 20L                  #
# Blum-Goldwasser Cipher     #
# Michał Kaniuk 295815       #
# Python 3.8.0 64-bit        #
##############################

import math
import random
import copy
import array
import binascii

# Extended Euclidean algorithm
def egcd(a, b):
	# Base Case  
    if a == 0 :   
        return b,0,1
             
    gcd,x1,y1 = egcd(b%a, a)  
     
    # Update x and y using results of recursive  
    x = y1 - (b//a) * x1  
    y = x1  

    return gcd,x,y 


# Key generation
def generate_key(p, q):
    # Two large distinct primes (p,q) - private key 
    # Compute n - public key
    n = p*q
    return n


### ENCRYPTION ###
def encryption(message, n):

    M = message
    M = M.replace(" ", "")  
    h = math.log2(math.log2(n)) # size of bit block
    h = int(h)+1 

    # Convert message into binary
    M_bin = ''.join(format(ord(i), 'b') for i in M) 
    print("Binary message = " + str(M_bin))
    M_bin = list(M_bin) # convert into list of bits

    # t - number of bit blocks
    if(len(M_bin)/h>int(len(M_bin)/h)):
        t = int(len(M_bin)/h) + 1
    else:
        t = int(len(M_bin)/h) 

    # Divide int blocks
    m = [str]*(t)
    for i in range(0, t):
        m[i] = M_bin[i*h:(i+1)*h]

    # Convert into decimal
    for i in range(0, t):
        if(m[i]==''):
            break
        m_temp = "".join(m[i])
        m_temp = int(m_temp, 2)
        m[i] = m_temp
        
    # Select random intiger r < n 
    r = random.randint(0, n)

    # x0 value
    x0 = (r**2)%n

    # Encryption loop
    M_encr = [int]*(t+1)
    M_encr[0] = x0
    xi = x0
    for i in range(0, t):
        xi = ((xi**2)%n)
        pi = xi&h
        ci = pi ^ m[i]
        M_encr[i] = ci

    # Last value = xt+1
    xi = (xi**2)%n
    M_encr[t] = xi

    l = len(M_bin) # message length
    k = (t-1)*h - l # number of bits in the last block

    # Convert into binary
    M_encrf = ""
    for i in range(0, t-1):
        if(i==t-2):
            tmp = bin(M_encr[i])[2:].zfill(h-k)
            M_encrf = M_encrf + tmp
        else:
            tmp = bin(M_encr[i])[2:].zfill(h)
            M_encrf = M_encrf + tmp
        
    # Encrypted message
    print("Encrypted binary message = " + str(M_encrf))
    
    return M_encr, l


### DECRYPTION ###
def decryption(message, p, q, l):

    n = p*q
    t = len(message)
    M_encr = message
    h = math.log2(math.log2(n))
    h = int(h)+1

    xi = message[t-1] 

    # Define parameters
    dp = (int((p+1)/4)**(t))%(p-1)
    dq = (int((q+1)/4)**(t))%(q-1)
    up = (xi**dp)%p
    uq = (xi**dq)%q
    gcd, rp, rq = egcd(p, q)

    # Define x0    
    x0 = (uq*rp*p+up*rq*q)%n
        
    # Decryption loop
    xi = x0
    M_decr = [int]*(t-1)
    M_decr[0] = message[t-1]
    for i in range(0, t-1):
        xi = (xi**2)%n
        pi = xi&h 
        mi = pi ^ M_encr[i]
        M_decr[i] = mi

    k = (t-1)*h - l #number of bits in the last block

    # Convert into binary
    M = ""
    for i in range(0, t-1):
        if(i==t-2):
            M_decr[i] = bin(M_decr[i])[2:].zfill(h-k)
            M = M + M_decr[i]
        else:
            M_decr[i] = bin(M_decr[i])[2:].zfill(h)
            M = M + M_decr[i]

    print("Decrypted binary message = " + str(M))

    # Convert into ascii 
    M_fin = ""
    for i in range(1, int(t)):
        if(M[7*(i-1):7*(i)]!=''):    
            tmp = chr(int(M[7*(i-1):7*(i)], 2))
            M_fin = M_fin + (tmp)

    # Decrypted message
    print("Decrypted message = " + str(M_fin))
    return M_decr
    
# TEST 1
M1 = "Message"
print("\nMessage = " + M1)
n = generate_key(19, 7) # key generation
M_encr, l = encryption(M1, n) # encryption
M_decr = decryption(M_encr, 19, 7, l) # decryption

# TEST 2
M2 = "Cryptography"
print("\nMessage = " + M2)
n = generate_key(191, 151) # key generation
M_encr, l = encryption(M2, n) # encryption
M_decr = decryption(M_encr, 191, 151, l) # decryption

# TEST 3
M3 = "Password"
print("\nMessage = " + M3)
n = generate_key(4423, 6067) # key generation
M_encr, l = encryption(M3, n) # encryption
M_decr = decryption(M_encr, 4423, 6067, l) # decryption
