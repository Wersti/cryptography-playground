
########################
# modern/pbkdf2.py (PBKDF2-HMAC-SHA256)
########################
from .hmac_sha256 import hmac_sha256

def _int_be(i: int) -> bytes:
    return i.to_bytes(4, 'big')

def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    hlen = 32
    blocks = (dklen + hlen - 1)//hlen
    out = b""
    for i in range(1, blocks+1):
        u = hmac_sha256(password, salt + _int_be(i))
        t = bytearray(u)
        for _ in range(iterations-1):
            u = hmac_sha256(password, u)
            t = bytearray(x ^ y for x,y in zip(t,u))
        out += bytes(t)
    return out[:dklen]


