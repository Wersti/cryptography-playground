########################
# tests/test_diffie_hellman.py
########################
from demos.diffie_hellman_demo import demo_values, dh_keypair, dh_shared_secret

def test_dh_shared_secret():
    p,g = demo_values()
    a,A = dh_keypair(p,g)
    b,B = dh_keypair(p,g)
    assert dh_shared_secret(p, B, a) == dh_shared_secret(p, A, b)