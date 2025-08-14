
########################
# app.py (Streamlit UI using from-scratch primitives)
########################
import base64
from io import BytesIO

import matplotlib.pyplot as plt
import streamlit as st

from classical.caesar_cipher import encrypt as caesar_enc, decrypt as caesar_dec
from classical.vigenere_cipher import encrypt as vig_enc, decrypt as vig_dec
from classical.vigenere_cracker import crack_vigenere, guess_key_length
from modern.sha256 import sha256
from modern.hmac_sha256 import hmac_sha256
from modern.pbkdf2 import pbkdf2_hmac_sha256
from modern.aes import aes_ctr_encrypt, aes_ctr_decrypt, randbytes
from modern.rsa import generate_rsa_keypair, rsa_encrypt_oaep, rsa_decrypt_oaep, rsa_sign_pss, rsa_verify_pss
from utils.text_tools import frequency_analysis

st.set_page_config(page_title="Crypto Playground", page_icon="🔐")
st.title("🔐 Crypto Playground — from scratch")
st.caption("Every primitive implemented in pure Python for learning. Not for production.")

mode = st.sidebar.selectbox(
    "Pick a module",
    [
        "Classical • Caesar",
        "Classical • Vigenère",
        "Classical • Frequency analysis",
        "Classical • Break Vigenère",
        "Modern • SHA-256 & HMAC & PBKDF2",
        "Modern • AES-CTR + HMAC (AEAD)",
        "Modern • RSA (OAEP / PSS)",
        "Modern • Diffie–Hellman & TLS demo",
    ],
)

if mode == "Classical • Caesar":
    st.header("Caesar Cipher")
    text = st.text_area("Plaintext", "attack at dawn")
    shift = st.slider("Shift", 0, 25, 3)
    ct = caesar_enc(text, shift)
    st.code(ct, language="text")
    st.text_input("Decrypt here", value=caesar_dec(ct, shift), disabled=True)

elif mode == "Classical • Vigenère":
    st.header("Vigenère Cipher")
    text = st.text_area("Plaintext", "defend the east wall")
    key = st.text_input("Key", "LEMON")
    ct = vig_enc(text, key)
    st.code(ct, language="text")
    st.text_input("Decrypt here", value=vig_dec(ct, key), disabled=True)

elif mode == "Classical • Frequency analysis":
    st.header("Frequency analysis (A–Z)")
    text = st.text_area("Text to analyze", "THIS IS JUST SOME SAMPLE TEXT TO SEE LETTER FREQUENCIES")
    freqs = frequency_analysis(text)
    letters = list(freqs.keys())
    values = list(freqs.values())
    fig = plt.figure()
    plt.bar(letters, values)
    plt.xlabel("Letter")
    plt.ylabel("Frequency")
    plt.title("Letter frequency")
    st.pyplot(fig)

elif mode == "Classical • Break Vigenère":
    st.header("Break Vigenère (educational)")
    ct = st.text_area("Ciphertext", "lxfopv ef rnhr")
    max_k = st.slider("Max key length to try", 2, 20, 12)
    if st.button("Guess key length"):
        klen = guess_key_length(ct, max_k=max_k)
        st.info(f"Guessed key length: {klen}")
    if st.button("Crack!"):
        key, pt = crack_vigenere(ct, max_k=max_k)
        st.success(f"Key ≈ {key}")
        st.code(pt)

elif mode == "Modern • SHA-256 & HMAC & PBKDF2":
    st.header("SHA‑256, HMAC‑SHA256, PBKDF2 (from scratch)")
    msg = st.text_input("Message", "hash me")
    st.write("SHA‑256:", sha256(msg.encode()).hex())
    key = st.text_input("HMAC key", "secret")
    st.write("HMAC‑SHA256:", hmac_sha256(key.encode(), msg.encode()).hex())
    pwd = st.text_input("Password for PBKDF2", "correct horse battery staple")
    salt = randbytes(16)
    iters = st.slider("Iterations", 1_000, 200_000, 50_000, step=1000)
    dklen = st.slider("Derived key bytes", 16, 64, 32, step=1)
    if st.button("Derive"):
        dk = pbkdf2_hmac_sha256(pwd.encode(), salt, iters, dklen)
        st.code(f"salt={base64.b64encode(salt).decode()}\ndk={base64.b64encode(dk).decode()}")

elif mode == "Modern • AES-CTR + HMAC (AEAD)":
    st.header("AES‑CTR + HMAC (Encrypt‑then‑MAC)")
    pt = st.text_area("Plaintext", "secrets go here")
    key = randbytes(16)
    nonce = randbytes(16)
    if st.button("Encrypt"):
        ct = aes_ctr_encrypt(pt.encode(), key, nonce)
        tag = hmac_sha256(key, nonce + ct)
        st.code(base64.b64encode(nonce + ct + tag).decode(), language="text")
    blob_b64 = st.text_area("Ciphertext+Tag (base64)", "")
    if st.button("Decrypt") and blob_b64:
        blob = base64.b64decode(blob_b64)
        nonce, rest = blob[:16], blob[16:]
        ct, tag = rest[:-32], rest[-32:]
        if hmac_sha256(key, nonce + ct) == tag:
            out = aes_ctr_decrypt(ct, key, nonce)
            st.success(out.decode())
        else:
            st.error("Tag mismatch: ciphertext altered")

elif mode == "Modern • RSA (OAEP / PSS)":
    st.header("RSA (from scratch): keygen, OAEP encrypt, PSS sign")
    bits = st.slider("Key size (educational)", 512, 2048, 1024, step=256)
    if st.button("Generate keypair"):
        n, e, d = generate_rsa_keypair(bits)
        st.session_state["rsa_key"] = (n, e, d)
        st.code(f"n=0x{n:x}\ne=0x{e:x}\nd=0x{d:x}")
    msg = st.text_input("Message", "hello rsa")
    if st.button("Encrypt (OAEP)"):
        n, e, d = st.session_state.get("rsa_key", (None, None, None))
        if n:
            ct = rsa_encrypt_oaep(msg.encode(), (n, e))
            st.session_state["rsa_ct"] = ct
            st.code(base64.b64encode(ct).decode())
        else:
            st.error("Generate a key first.")
    if st.button("Decrypt (OAEP)"):
        n, e, d = st.session_state.get("rsa_key", (None, None, None))
        ct = st.session_state.get("rsa_ct")
        if n and ct:
            pt = rsa_decrypt_oaep(ct, (n, d))
            st.success(pt.decode())
        else:
            st.error("Need key and ciphertext.")
    if st.button("Sign (PSS)"):
        n, e, d = st.session_state.get("rsa_key", (None, None, None))
        if n:
            sig = rsa_sign_pss(msg.encode(), (n, d))
            st.session_state["rsa_sig"] = sig
            st.code(base64.b64encode(sig).decode())
        else:
            st.error("Generate a key first.")
    if st.button("Verify (PSS)"):
        n, e, d = st.session_state.get("rsa_key", (None, None, None))
        sig = st.session_state.get("rsa_sig")
        if n and sig:
            ok = rsa_verify_pss(msg.encode(), sig, (n, e))
            st.success(f"Valid: {ok}")
        else:
            st.error("Need public key and signature.")

elif mode == "Modern • Diffie–Hellman & TLS demo":
    st.header("Diffie–Hellman (integers mod p) & TLS-style demo")
    from demos.diffie_hellman_demo import demo_values
    from demos.tls_handshake_demo import tls_demo
    p, g = demo_values()
    st.write("Public parameters:")
    st.code(f"p=0x{p:x}\ng={g}")
    if st.button("Run handshake"):
        transcript = tls_demo()
        st.code("\n".join(transcript))

