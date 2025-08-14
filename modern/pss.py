
########################
# modern/pss.py (RSA-PSS)
########################
from .sha256 import sha256
from .oaep import mgf1
import os

def pss_encode(mhash: bytes, emlen: int, sLen: int=32) -> bytes:
    salt = os.urandom(sLen)
    mprime = b"\x00"*8 + mhash + salt
    h = sha256(mprime)
    ps = b"\x00"*(emlen - sLen - 2 - len(h))
    db = ps + b"\x01" + salt
    db_mask = mgf1(h, emlen - len(h) - 1)
    maskedDB = bytes(x^y for x,y in zip(db, db_mask))
    return maskedDB + h + b"\xbc"

def pss_verify(mhash: bytes, em: bytes, sLen: int=32) -> bool:
    if em[-1] != 0xbc:
        return False
    emlen = len(em)
    h = em[emlen-33:emlen-1]
    maskedDB = em[:emlen-33]
    db_mask = mgf1(h, len(maskedDB))
    db = bytes(x^y for x,y in zip(maskedDB, db_mask))
    # split
    try:
        idx = db.index(b"\x01")
    except ValueError:
        return False
    salt = db[idx+1:]
    mprime = b"\x00"*8 + mhash + salt
    return sha256(mprime) == h


