########################
# tests/test_aes_ctr_aead.py
########################
from modern.aes import aes_ctr_encrypt, aes_ctr_decrypt

def test_ctr_roundtrip():
    key = b"\x00"*16
    nonce = b"\x00"*16
    pt = b"\x00"*64
    ct = aes_ctr_encrypt(pt, key, nonce)
    assert aes_ctr_decrypt(ct, key, nonce) == pt
