
########################
# classical/caesar_cipher.py
########################
import string

ALPHABET = string.ascii_lowercase


def _shift_char(c: str, k: int) -> str:
    if c.lower() not in ALPHABET:
        return c
    idx = ALPHABET.index(c.lower())
    out = ALPHABET[(idx + k) % 26]
    return out.upper() if c.isupper() else out


def encrypt(text: str, shift: int) -> str:
    """Caesar encryption (educational)."""
    return "".join(_shift_char(c, shift) for c in text)


def decrypt(text: str, shift: int) -> str:
    return encrypt(text, -shift)

