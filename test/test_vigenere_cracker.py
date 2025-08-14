
########################
# tests/test_vigenere_cracker.py
########################
from classical.vigenere_cipher import encrypt
from classical.vigenere_cracker import crack_vigenere

def test_cracker_basic():
    pt = "DEFENDTHEEASTWALL"
    key = "LEMON"
    ct = encrypt(pt, key)
    guessed_key, out = crack_vigenere(ct, max_k=8)
    assert out.upper().startswith("DEFEND")

