# pip install pqcrypto cryptography
from pqcrypto.kem.ml_kem_512 import generate_keypair, encrypt, decrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

# Kyber key exchange
pk, sk = generate_keypair()
ciphertext, shared_secret_B = encrypt(pk)
shared_secret_A = decrypt(sk, ciphertext)
assert shared_secret_A == shared_secret_B

# Derive symmetric key from shared secret using HKDF
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,        # 32 bytes = 256-bit key
    salt=None,        # optional, can be a random 32-byte salt
    info=b'psm-session-key'
)
symmetric_key = hkdf.derive(shared_secret_A)

# ChaCha20-Poly1305 encryption
aead = ChaCha20Poly1305(symmetric_key)
nonce = os.urandom(12)  # unique per message
plaintext = b"yo this is a secret message"
ciphertext = aead.encrypt(nonce, plaintext, None)
print("Ciphertext:", ciphertext.hex())

# Decryption
decrypted = aead.decrypt(nonce, ciphertext, None)
print("Decrypted:", decrypted)
