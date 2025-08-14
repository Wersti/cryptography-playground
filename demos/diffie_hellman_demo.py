
########################
# demos/diffie_hellman_demo.py
########################
"""Simple Diffie–Hellman over integers mod p (educational)."""
import os

def demo_values():
    # 1536-bit safe prime would be nicer; use small for speed here
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" \
        "8AC723A70A0E5F", 16
    )  # short placeholder prime
    g = 5
    return p, g


def dh_keypair(p: int, g: int):
    a = int.from_bytes(os.urandom(32), 'big') % (p-2) + 2
    A = pow(g, a, p)
    return a, A


def dh_shared_secret(p: int, A: int, b: int):
    return pow(A, b, p)

