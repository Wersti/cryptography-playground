
########################
# classical/vigenere_cipher.py
########################
import string

ALPHABET = string.ascii_uppercase


def _clean_key(key: str) -> str:
    k = [c for c in key.upper() if c in ALPHABET]
    if not k:
        raise ValueError("Key must contain letters")
    return "".join(k)


def encrypt(text: str, key: str) -> str:
    key = _clean_key(key)
    out, j = [], 0
    for c in text:
        if c.upper() in ALPHABET:
            p = ALPHABET.index(c.upper())
            k = ALPHABET.index(key[j % len(key)])
            ct = ALPHABET[(p + k) % 26]
            out.append(ct if c.isupper() else ct.lower())
            j += 1
        else:
            out.append(c)
    return "".join(out)


def decrypt(text: str, key: str) -> str:
    key = _clean_key(key)
    out, j = [], 0
    for c in text:
        if c.upper() in ALPHABET:
            p = ALPHABET.index(c.upper())
            k = ALPHABET.index(key[j % len(key)])
            pt = ALPHABET[(p - k) % 26]
            out.append(pt if c.isupper() else pt.lower())
            j += 1
        else:
            out.append(c)
    return "".join(out)

