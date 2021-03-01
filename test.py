import math
import random
import copy
import array
import binascii

def euclidian_gcd(a, b):  
    if a == 0 :   
        return b,0,1

    gcd,x1,y1 = egcd(b%a, a)    
    x = y1 - (b//a) * x1  
    y = x1  
return gcd,x,y 

def generate_key(p, q):
    n = p*q
return n

def encryption(m, n):
    message = m
    message = message.replace(" ", "")  
    h = math.log2(math.log2(n))
    h = int(h)+1 
    message_bin = ''.join(format(ord(i), 'b') for i in message) 
    print("Binary m = " + str(message_bin))
    message_bin = list(message_bin)

    if(len(message_bin)/h>int(len(message_bin)/h)):
        t = int(len(message_bin)/h) + 1
    else:
        t = int(len(message_bin)/h) 

    m = [str]*(t)
    for i in range(0, t):
        m[i] = message_bin[i*h:(i+1)*h]

    for i in range(0, t):
        if(m[i]==''):
            break
        m_temp = "".join(m[i])
        m_temp = int(m_temp, 2)
        m[i] = m_temp
         
    r = random.randint(0, n)
    x0 = (r**2)%n

    message_encr = [int]*(t+1)
    message_encr[0] = x0
    xi = x0
    for i in range(0, t):
        xi = ((xi**2)%n)
        pi = xi&h
        ci = pi ^ m[i]
        message_encr[i] = ci

    xi = (xi**2)%n
    message_encr[t] = xi
    l = len(message_bin) 
    k = (t-1)*h - l 

    M_encrf = ""
    for i in range(0, t-1):
        if(i==t-2):
            tmp = bin(message_encr[i])[2:].zfill(h-k)
            M_encrf = M_encrf + tmp
        else:
            tmp = bin(message_encr[i])[2:].zfill(h)
            M_encrf = M_encrf + tmp
        
    print("Encrypted binary m = " + str(M_encrf))
    
return message_encr, l

def decryption(m, p, q, l):
    n = p*q
    t = len(m)
    message_encr = m
    h = math.log2(math.log2(n))
    h = int(h)+1
    xi = m[t-1] 

    dp = (int((p+1)/4)**(t))%(p-1)
    dq = (int((q+1)/4)**(t))%(q-1)
    up = (xi**dp)%p
    uq = (xi**dq)%q
    gcd, rp, rq = egcd(p, q)

    x0 = (uq*rp*p+up*rq*q)%n
        
    xi = x0
    message_decr = [int]*(t-1)
    message_decr[0] = m[t-1]
    for i in range(0, t-1):
        xi = (xi**2)%n
        pi = xi&h 
        mi = pi ^ message_encr[i]
        message_decr[i] = mi

    k = (t-1)*h - l 

    message = ""
    for i in range(0, t-1):
        if(i==t-2):
            message_decr[i] = bin(message_decr[i])[2:].zfill(h-k)
            message = message + message_decr[i]
        else:
            message_decr[i] = bin(message_decr[i])[2:].zfill(h)
            message = message + message_decr[i]

    print("Decrypted binary m = " + str(message))

    M_fin = ""
    for i in range(1, int(t)):
        if(message[7*(i-1):7*(i)]!=''):    
            tmp = chr(int(message[7*(i-1):7*(i)], 2))
            M_fin = M_fin + (tmp)

    print("Decrypted m = " + str(M_fin))
    return message_decr
    
# TEST 1
M1 = "m"
print("\nm = " + M1)
n = generate_key(19, 7) # key generation
message_encr, l = encryption(M1, n) # encryption
message_decr = decryption(message_encr, 19, 7, l) # decryption

# TEST 2
M2 = "Cryptography"
print("\nm = " + M2)
n = generate_key(191, 151) # key generation
message_encr, l = encryption(M2, n) # encryption
message_decr = decryption(message_encr, 191, 151, l) # decryption

# TEST 3
M3 = "Password"
print("\nm = " + M3)
n = generate_key(4093, 5344) # key generation
message_encr, l = encryption(M3, n) # encryption
message_decr = decryption(message_encr, 4093, 5344, l) # decryption
