
########################
# tests/test_rsa_oaep_pss.py
########################
from modern.rsa import generate_rsa_keypair, rsa_encrypt_oaep, rsa_decrypt_oaep, rsa_sign_pss, rsa_verify_pss

def test_rsa_roundtrip_small():
    n,e,d = generate_rsa_keypair(512)
    msg = b"hi"
    ct = rsa_encrypt_oaep(msg, (n,e))
    pt = rsa_decrypt_oaep(ct, (n,d))
    assert pt == msg


def test_pss_sign_verify():
    n,e,d = generate_rsa_keypair(512)
    msg = b"message"
    sig = rsa_sign_pss(msg, (n,d))
    assert rsa_verify_pss(msg, sig, (n,e))


