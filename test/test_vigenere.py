
########################
# tests/test_vigenere.py
########################
from classical.vigenere_cipher import encrypt, decrypt

def test_roundtrip_key_cases():
    pt = "Attack at dawn!"
    key = "LeMon"
    assert decrypt(encrypt(pt, key), key) == pt


