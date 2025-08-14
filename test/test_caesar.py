
########################
# tests/test_caesar.py
########################
from classical.caesar_cipher import encrypt, decrypt

def test_roundtrip_simple():
    pt = "Hello, World!"
    for k in range(26):
        assert decrypt(encrypt(pt, k), k) == pt

