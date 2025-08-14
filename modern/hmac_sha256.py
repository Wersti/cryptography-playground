
########################
# modern/hmac_sha256.py (pure python HMAC using our SHA-256)
########################
from .sha256 import sha256

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    block = 64
    if len(key) > block:
        key = sha256(key)
    key = key + b"\x00"*(block-len(key))
    o_key_pad = bytes((k ^ 0x5c) for k in key)
    i_key_pad = bytes((k ^ 0x36) for k in key)
    return sha256(o_key_pad + sha256(i_key_pad + data))


