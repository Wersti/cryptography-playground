
########################
# README.md
########################

# crypto-playground (from-scratch edition)

Educational repository implementing **cryptographic primitives from scratch in pure Python** — no crypto libraries. Everything includes step-by-step comments and docstrings.

> ⚠️ **For learning only**. Implementations are intentionally simple and **not constant-time**. Do **not** use for real security.

## Contents
- Classical: Caesar, Vigenère, frequency analysis, Vigenère cracker.
- Modern (from scratch):
  - SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256
  - AES-128 (key schedule, S-box, ECB/CTR), AEAD via **Encrypt-then-MAC** (AES-CTR + HMAC)
  - RSA (keygen with Miller–Rabin, OAEP encryption, PSS signatures)
  - Diffie–Hellman (integer group) & simplified TLS-style handshake demo
- Streamlit app to interact with all modules (uses only our code).

## Quickstart
```bash
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run the web playground
streamlit run app.py

# Run tests
pytest -q
```

## License
MIT — see `LICENSE`.