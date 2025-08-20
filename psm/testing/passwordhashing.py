# yes i know this is gpt but atleast it can write code so i dont give a fuck

from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type
import os
import base64

# --- CLIENT SIDE ---
def client_hash(password: str, salt: bytes) -> str:
    # Derive a fixed-length client hash with known salt
    hash_bytes = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )
    return base64.b64encode(hash_bytes).decode()

# Client generates or stores a fixed salt
client_salt = b'my_fixed_client_salt'  # Must be same for this client
password = "hi"
client_derived = client_hash(password, client_salt)
print("Client hash sent over:", client_derived)


# --- SERVER SIDE ---
# Server can add its own salt and hash the client-derived value
server_salt = os.urandom(16)  # random per-user server salt
ph = PasswordHasher()

# Server hashes the client hash (like a normal password hash)
server_stored_hash = ph.hash(client_derived + base64.b64encode(server_salt).decode())
print("Server stored hash:", server_stored_hash)

# --- VERIFICATION ---
def verify_server(client_hash_sent: str, stored_hash: str, server_salt: bytes) -> bool:
    try:
        return ph.verify(stored_hash, client_hash_sent + base64.b64encode(server_salt).decode())
    except Exception:
        return False

# Test verification
print("Verified?", verify_server(client_derived, server_stored_hash, server_salt))