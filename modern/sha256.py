
########################
# modern/sha256.py (pure python SHA-256)
########################
"""SHA-256 from scratch (educational, not constant-time)."""
from typing import Iterable

# Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]
# Round constants (first 32 bits of fractional parts of cube roots of 1..64 primes)
K = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]

def _rotr(x,n): return ((x>>n)|(x<<(32-n))) & 0xffffffff

def _ch(x,y,z): return (x & y) ^ (~x & z)

def _maj(x,y,z): return (x & y) ^ (x & z) ^ (y & z)

def _bsig0(x): return _rotr(x,2) ^ _rotr(x,13) ^ _rotr(x,22)

def _bsig1(x): return _rotr(x,6) ^ _rotr(x,11) ^ _rotr(x,25)

def _ssig0(x): return _rotr(x,7) ^ _rotr(x,18) ^ (x>>3)

def _ssig1(x): return _rotr(x,17) ^ _rotr(x,19) ^ (x>>10)


def _pad(msg: bytes) -> bytes:
    ml = len(msg) * 8
    msg += b"\x80"
    while ((len(msg) * 8) % 512) != 448:
        msg += b"\x00"
    msg += ml.to_bytes(8, 'big')
    return msg


def sha256(data: bytes) -> bytes:
    h = H0[:]
    m = _pad(data)
    for i in range(0, len(m), 64):
        chunk = m[i:i+64]
        w = [int.from_bytes(chunk[j:j+4], 'big') for j in range(0,64,4)]
        for j in range(16, 64):
            w.append( (_ssig1(w[j-2]) + w[j-7] + _ssig0(w[j-15]) + w[j-16]) & 0xffffffff )
        a,b,c,d,e,f,g,hh = h
        for j in range(64):
            t1 = (hh + _bsig1(e) + _ch(e,f,g) + K[j] + w[j]) & 0xffffffff
            t2 = (_bsig0(a) + _maj(a,b,c)) & 0xffffffff
            hh = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff
        h = [(x+y) & 0xffffffff for x,y in zip(h,[a,b,c,d,e,f,g,hh])]
    return b''.join(x.to_bytes(4,'big') for x in h)


