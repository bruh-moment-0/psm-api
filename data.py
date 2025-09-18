# tried using SQL but i guess its ass cheeks so time to make my own with json (aka. the best data storage type)

from typing import Any
import datetime # i normally go with time but thats just not cool as this
import base64
import json # "in json we believe" - json cult /s
import os

VERSION = "API V1.1.8 STABLE (built 20:45 GMT+0 13/09/2025)"
BASEDIR = os.path.abspath(os.path.dirname(__file__))
DOTENV_PATH = os.path.join(BASEDIR, ".env")
STORAGE = os.path.join(BASEDIR, "storage")
BASEMESSAGEDIR = os.path.join(STORAGE, "messages")
MESSAGECOUNTERDIR = os.path.join(BASEMESSAGEDIR, "messagecounter")
USERCOUNTERDIR = os.path.join(BASEMESSAGEDIR, "usercounter")
MESSAGEDIR = os.path.join(BASEMESSAGEDIR, "messages")
USERDIR = os.path.join(STORAGE, "users")
AUTHCHALLENGEDIR = os.path.join(STORAGE, "challenge")

os.makedirs(STORAGE, exist_ok=True)
os.makedirs(BASEMESSAGEDIR, exist_ok=True)
os.makedirs(MESSAGECOUNTERDIR, exist_ok=True)
os.makedirs(USERCOUNTERDIR, exist_ok=True)
os.makedirs(MESSAGEDIR, exist_ok=True)
os.makedirs(USERDIR, exist_ok=True)
os.makedirs(AUTHCHALLENGEDIR, exist_ok=True)

def b64encodeUrlSafe(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode()

def b64decodeUrlSafe(s: str) -> bytes:
    return base64.urlsafe_b64decode(s)

def str2byte(text: str) -> bytes:
    byte = text.encode('utf-8')
    return byte

def byte2str(bytetext: bytes) -> str:
    text = bytetext.decode('utf-8')
    return text

def byte2b64(bytetext: bytes) -> str:
    return base64.b64encode(bytetext).decode()

def b642byte(b64text: str) -> bytes:
    return base64.b64decode(b64text.encode())

def writejson(filepath: str, data: Any, indent: int = 4) -> None:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent)

def readjson(filepath: str) -> dict:
    if not os.path.exists(filepath):
        data = {}
        writejson(filepath, data)
        return data
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)

class UserExistsError(Exception):
    pass

class UserClass:
    def __init__(self, username: str, publickey_kyber: str, publickey_ed25519):
        filepath = os.path.join(USERDIR, f"{username}-V1.json")
        if os.path.exists(filepath):
            raise UserExistsError(f"username {username} exists")
        self.username = username
        self.creation = datetime.datetime.now(datetime.timezone.utc)
        self.publickey_kyber = publickey_kyber
        self.publickey_ed25519 = publickey_ed25519
    def out(self):
        return {
            "ver": VERSION,
            "type": "class User",
            "username": self.username,
            "publickey_kyber": self.publickey_kyber,
            "publickey_ed25519": self.publickey_ed25519,
            "creation": int(self.creation.timestamp())
        }