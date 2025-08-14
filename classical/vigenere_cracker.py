
########################
# classical/vigenere_cracker.py
########################
"""Educational Vigenère cracker using index of coincidence and frequency matching."""
from collections import Counter
import string

ALPHABET = string.ascii_uppercase
ENG_FREQ = {
    'A': 0.082, 'B': 0.015, 'C': 0.028, 'D': 0.043, 'E': 0.127,
    'F': 0.022, 'G': 0.020, 'H': 0.061, 'I': 0.070, 'J': 0.002,
    'K': 0.008, 'L': 0.040, 'M': 0.024, 'N': 0.067, 'O': 0.075,
    'P': 0.019, 'Q': 0.001, 'R': 0.060, 'S': 0.063, 'T': 0.091,
    'U': 0.028, 'V': 0.010, 'W': 0.023, 'X': 0.001, 'Y': 0.020, 'Z': 0.001
}

def _clean(t: str) -> str:
    return ''.join([c for c in t.upper() if c in ALPHABET])


def index_of_coincidence(t: str) -> float:
    t = _clean(t)
    n = len(t)
    if n < 2:
        return 0.0
    cnt = Counter(t)
    return sum(f*(f-1) for f in cnt.values()) / (n*(n-1))


def guess_key_length(ct: str, max_k: int = 16) -> int:
    ct = _clean(ct)
    best_k, best_score = 1, 0.0
    for k in range(1, max_k+1):
        cols = ['' for _ in range(k)]
        for i, ch in enumerate(ct):
            cols[i % k] += ch
        ic = sum(index_of_coincidence(col) for col in cols) / k
        if ic > best_score:
            best_score, best_k = ic, k
    return best_k


def _rotate(s: str, r: int) -> str:
    return ''.join(ALPHABET[(ALPHABET.index(c)-r) % 26] for c in s)


def _chi2(obs_counts, exp_freq, n):
    return sum(((obs_counts.get(c,0) - n*exp_freq[c])**2) / (n*exp_freq[c] or 1e-9) for c in ALPHABET)


def crack_vigenere(ct: str, max_k: int = 16):
    c = _clean(ct)
    klen = guess_key_length(c, max_k)
    key = []
    for i in range(klen):
        col = c[i::klen]
        n = len(col)
        counts = Counter(col)
        # try all shifts and pick the one minimizing chi-square to English
        best_shift, best_score = 0, 1e9
        for s in range(26):
            rotated = _rotate(col, s)
            counts_r = Counter(rotated)
            score = _chi2(counts_r, ENG_FREQ, n)
            if score < best_score:
                best_score, best_shift = score, s
        key.append(ALPHABET[best_shift])
    key_str = ''.join(key)
    # decrypt
    from .vigenere_cipher import decrypt
    pt = decrypt(ct, key_str)
    return key_str, pt

