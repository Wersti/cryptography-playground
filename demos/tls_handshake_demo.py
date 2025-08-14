
########################
# demos/tls_handshake_demo.py
########################
from .diffie_hellman_demo import demo_values, dh_keypair, dh_shared_secret
from modern.sha256 import sha256
from modern.hmac_sha256 import hmac_sha256


def tls_demo():
    transcript = []
    p, g = demo_values()
    a, A = dh_keypair(p,g)
    b, B = dh_keypair(p,g)
    transcript.append(f"Client sends A={A}")
    transcript.append(f"Server sends B={B}")
    ss_client = dh_shared_secret(p, B, a)
    ss_server = dh_shared_secret(p, A, b)
    transcript.append(f"Shared secret match: {ss_client==ss_server}")
    master = sha256(ss_client.to_bytes((ss_client.bit_length()+7)//8,'big'))
    transcript.append(f"Master secret (SHA-256) = {master.hex()}")
    key_client = hmac_sha256(b"key client", master)
    key_server = hmac_sha256(b"key server", master)
    transcript.append(f"Client key = {key_client.hex()[:16]}…")
    transcript.append(f"Server key = {key_server.hex()[:16]}…")
    return transcript


