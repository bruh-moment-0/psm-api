# tried using SQL but i guess its ass cheeks so time to make my own with json (aka. the best data storage type)

from argon2 import PasswordHasher
from typing import Any
import datetime # i normally go with time but thats just not cool as this
import hashlib
import base64
import json # "in json we believe" - json cult /s
import os

ph = PasswordHasher()
VERSION = "V1"

BASEDIR = os.path.abspath(os.path.dirname(__file__))
USERDIR = os.path.join(BASEDIR, "users")

def str2byte(text: str) -> bytes:
    byte = text.encode('utf-8')
    return byte

def byte2str(bytetext: bytes) -> str:
    text = bytetext.decode('utf-8')
    return text

def byte2b64(bytetext: bytes) -> str:
    return base64.b64encode(bytetext).decode()

def hash_sha3_512(data: bytes) -> str:
    return hashlib.sha3_512(data).hexdigest()

def writejson(filepath: str, data: Any, indent: int = 4) -> None:
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
    def __init__(self, username: str, clientsalt: bytes, clienthashed: str, publickey: str):
        filepath = os.path.join(USERDIR, f"{username}-V1.json")
        if os.path.exists(filepath):
            raise UserExistsError(f"username {username} exists")
        self.username = username
        self.creation = datetime.datetime.now(datetime.timezone.utc)
        self.clientsalt = clientsalt
        self.clienthashed = clienthashed
        self.serversalt = os.urandom(16)
        self.serverstoredhash = ph.hash(self.clienthashed + byte2b64(self.serversalt))
        self.publickey = publickey
        data = {
            "ver": VERSION,
            "type": "class User",
            "username": self.username,
            "creation": int(self.creation.timestamp()),
            "clientsalt": byte2b64(self.clientsalt),
            "clienthashed": self.clienthashed,
            "serversalt": byte2b64(self.serversalt),
            "serverhashed": self.serverstoredhash,
            "publickey": self.publickey
        }
        writejson(filepath, data)

if __name__ == "__main__":
    try:
        UserClass("testuser", b"testclientsalt", "testclienthashed", "testpublickey")
    except UserExistsError as e:
        print(e)