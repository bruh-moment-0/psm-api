# quantum.py for post quantum functions
# 02/11/2025

from typing import Optional, Tuple, Any
import oqs

# sign algos:
# print(oqs.get_enabled_sig_mechanisms())
# kem algos:
# print(oqs.get_enabled_kem_mechanisms())

ML_DSA_ALGO = "ML-DSA-65" # ML-DSA-44, ML-DSA-65, ML-DSA-87
KEM_ALGO = "Kyber768" # ("Kyber512", "Kyber768", "Kyber1024")

def sign_obj_create(privkey: Optional[bytes] = None) -> oqs.Signature:
    sig = oqs.Signature(ML_DSA_ALGO, secret_key=privkey)
    return sig

def kem_obj_create(privkey: Optional[bytes] = None) -> oqs.KeyEncapsulation:
    kem_obj = oqs.KeyEncapsulation(KEM_ALGO, secret_key=privkey)
    return kem_obj

def create_key_pair(obj: Any) -> Tuple[bytes, bytes]:
    pubkey: bytes = obj.generate_keypair()
    privkey: bytes = obj.export_secret_key()
    return pubkey, privkey

def sign(sign_obj: oqs.Signature, message: bytes) -> bytes:
    signature: bytes = sign_obj.sign(message)
    return signature

def verify(sign_obj: oqs.Signature, message: bytes, signature: bytes, pubkey: bytes) -> bool:
    valid: bool = sign_obj.verify(message, signature, pubkey)
    return valid

def encap(kem_obj: oqs.KeyEncapsulation, pubkey: bytes) -> Tuple[bytes, bytes]:
    ciphertext, sharedsecret = kem_obj.encap_secret(pubkey)
    return ciphertext, sharedsecret

def decap(kem_obj: oqs.KeyEncapsulation, ciphertext: bytes) -> bytes:
    sharedsecret: bytes = kem_obj.decap_secret(ciphertext)
    return sharedsecret

if __name__ == "__main__":
    import base64
    def byte2b64(bytetext: bytes) -> str:
        return base64.b64encode(bytetext).decode()
    def b642byte(b64text: str) -> bytes:
        return base64.b64decode(b64text.encode())
    sign_connection = sign_obj_create()
    public, private = create_key_pair(sign_connection)
    print(byte2b64(public))
    print(byte2b64(private))