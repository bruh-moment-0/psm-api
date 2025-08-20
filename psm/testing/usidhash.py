import hashlib

def id_shake256_256(data: bytes) -> str:
    return hashlib.shake_256(data).hexdigest(32)  # 32 bytes = 256 bits

def id_shake256_512(data: bytes) -> str:
    return hashlib.shake_256(data).hexdigest(64)  # 64 bytes = 512 bits

def id_sha3_512(data: bytes) -> str:
    return hashlib.sha3_512(data).hexdigest()

# example usage
print("256-bit:", id_shake256_256(b"hello world"))
print("512-bit:", id_shake256_512(b"hello world"))
print("sha3-512:", id_sha3_512(b"hello world"))