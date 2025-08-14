
########################
# tests/test_hmac_pbkdf2.py
########################
from modern.hmac_sha256 import hmac_sha256
from modern.pbkdf2 import pbkdf2_hmac_sha256

def test_hmac_vector():
    # RFC 4231 test case 1
    key = b"\x0b"*20
    data = b"Hi There"
    assert hmac_sha256(key, data).hex() == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"


def test_pbkdf2_len():
    dk = pbkdf2_hmac_sha256(b"password", b"salt", 1, 32)
    assert len(dk) == 32


