
########################
# modern/rsa.py (keygen, encrypt/decrypt, sign/verify)
########################
import os
from .sha256 import sha256
from .oaep import oaep_encode, oaep_decode
from .pss import pss_encode, pss_verify

# --- number theory helpers ---

def egcd(a,b):
    if b==0:
        return (a,1,0)
    g,x1,y1 = egcd(b, a%b)
    return (g, y1, x1 - (a//b)*y1)

def modinv(a,m):
    g,x,y = egcd(a,m)
    if g!=1: raise ValueError("no inverse")
    return x % m

# Miller–Rabin primality test
_DEF_BASES = [2,3,5,7,11,13,17,19,23,29,31,37]

def is_probable_prime(n:int) -> bool:
    if n<2: return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n%p==0:
            return n==p
    # write n-1 = d*2^s
    d = n-1
    s = 0
    while d%2==0:
        d//=2; s+=1
    import random
    for a in _DEF_BASES:
        if a % n == 0:
            continue
        x = pow(a,d,n)
        if x==1 or x==n-1:
            continue
        for _ in range(s-1):
            x = (x*x)%n
            if x==n-1:
                break
        else:
            return False
    return True


def random_prime(bits:int)->int:
    while True:
        cand = int.from_bytes(os.urandom(bits//8), 'big') | 1 | (1<<(bits-1))
        if is_probable_prime(cand):
            return cand


def generate_rsa_keypair(bits:int=1024):
    e = 65537
    p = random_prime(bits//2)
    q = random_prime(bits//2)
    n = p*q
    phi = (p-1)*(q-1)
    d = modinv(e, phi)
    return (n, e, d)


def rsa_encrypt_oaep(message: bytes, pub: tuple[int,int]) -> bytes:
    n,e = pub
    k = (n.bit_length()+7)//8
    em = oaep_encode(message, k)
    m = int.from_bytes(em, 'big')
    c = pow(m, e, n)
    return c.to_bytes(k, 'big')


def rsa_decrypt_oaep(ciphertext: bytes, prv: tuple[int,int]) -> bytes:
    n,d = prv
    k = (n.bit_length()+7)//8
    c = int.from_bytes(ciphertext, 'big')
    m = pow(c, d, n)
    em = m.to_bytes(k, 'big')
    return oaep_decode(em)


def rsa_sign_pss(message: bytes, prv: tuple[int,int]) -> bytes:
    n,d = prv
    k = (n.bit_length()+7)//8
    mhash = sha256(message)
    em = pss_encode(mhash, k-1)  # leave one byte for zero-leading when needed
    s = pow(int.from_bytes(em,'big'), d, n)
    return s.to_bytes(k, 'big')


def rsa_verify_pss(message: bytes, signature: bytes, pub: tuple[int,int]) -> bool:
    n,e = pub
    k = (n.bit_length()+7)//8
    s = int.from_bytes(signature, 'big')
    em = pow(s, e, n).to_bytes(k, 'big')
    mhash = sha256(message)
    return pss_verify(mhash, em)

