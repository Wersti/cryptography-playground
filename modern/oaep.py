
########################
# modern/oaep.py (MGF1 + OAEP using our SHA-256)
########################
from .sha256 import sha256

def mgf1(seed: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += sha256(seed + counter.to_bytes(4,'big'))
        counter += 1
    return out[:length]


def oaep_encode(message: bytes, k: int, label: bytes=b"") -> bytes:
    # k = modulus byte length
    hlen = 32
    mlen = len(message)
    if mlen > k - 2*hlen - 2:
        raise ValueError("message too long")
    lhash = sha256(label)
    ps = b"\x00"*(k - mlen - 2*hlen - 2)
    db = lhash + ps + b"\x01" + message
    seed = os.urandom(hlen)
    db_mask = mgf1(seed, k - hlen - 1)
    masked_db = bytes(x^y for x,y in zip(db, db_mask))
    seed_mask = mgf1(masked_db, hlen)
    masked_seed = bytes(x^y for x,y in zip(seed, seed_mask))
    return b"\x00" + masked_seed + masked_db


def oaep_decode(em: bytes, label: bytes=b"") -> bytes:
    hlen = 32
    if em[0] != 0:
        raise ValueError("decryption error")
    masked_seed = em[1:1+hlen]
    masked_db = em[1+hlen:]
    seed_mask = mgf1(masked_db, hlen)
    seed = bytes(x^y for x,y in zip(masked_seed, seed_mask))
    db_mask = mgf1(seed, len(masked_db))
    db = bytes(x^y for x,y in zip(masked_db, db_mask))
    lhash = sha256(label)
    if db[:hlen] != lhash:
        raise ValueError("decryption error")
    i = db.find(b"\x01", hlen)
    if i == -1:
        raise ValueError("decryption error")
    return db[i+1:]


