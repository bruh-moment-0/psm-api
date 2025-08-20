# pip install pqcrypto
from pqcrypto.kem.ml_kem_512 import generate_keypair, encrypt, decrypt

# User A generates keypair
pk, sk = generate_keypair()

# User B encrypts a shared secret to User A
ciphertext, shared_secret_B = encrypt(pk)

# User A decrypts the ciphertext
shared_secret_A = decrypt(sk, ciphertext)

print(f"shared secret match:{shared_secret_A == shared_secret_B}")
print(f"shared secret A: {shared_secret_A} shared secret B: {shared_secret_B}")