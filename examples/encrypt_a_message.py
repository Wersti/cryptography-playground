
########################
# examples/encrypt_a_message.py
########################
from classical.caesar_cipher import encrypt as caesar
from modern.aes import aes_ctr_encrypt, aes_ctr_decrypt, randbytes
from modern.hmac_sha256 import hmac_sha256

if __name__ == "__main__":
    print("Caesar demo:")
    msg = "attack at dawn"
    ct = caesar(msg, 3)
    print("  ", msg, "->", ct)

    print("\nAES‑CTR + HMAC demo:")
    key = randbytes(16); nonce = randbytes(16)
    pt = b"hello"
    ct = aes_ctr_encrypt(pt, key, nonce)
    tag = hmac_sha256(key, nonce + ct)
    print("  tag:", tag.hex())
    dec = aes_ctr_decrypt(ct, key, nonce)
    print("  decrypted:", dec)


