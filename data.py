# tried using SQL but i guess its ass cheeks so time to make my own with json (aka. the best data storage type)

from typing import Any
import datetime # i normally go with time but thats just not cool as this
import base64
import json # "in json we believe" - json cult /s
import os


VERSION = "V1"


BASEDIR = os.path.abspath(os.path.dirname(__file__))
DOTENV_PATH = os.path.join(BASEDIR, ".env")
MESSAGEDIR = os.path.join(BASEDIR, "messages")
STORAGE = os.path.join(BASEDIR, "storage")
USERDIR = os.path.join(STORAGE, "users")
AUTHCHALLENGEDIR = os.path.join(STORAGE, "challenge")

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
    def __init__(self, username: str, publickey: str):
        filepath = os.path.join(USERDIR, f"{username}-V1.json")
        if os.path.exists(filepath):
            raise UserExistsError(f"username {username} exists")
        self.username = username
        self.creation = datetime.datetime.now(datetime.timezone.utc)
        self.serversalt = os.urandom(16)
        self.publickey = publickey
        data = {
            "ver": VERSION,
            "type": "class User",
            "username": self.username,
            "publickey": publickey,
            "creation": int(self.creation.timestamp()),
            "serversalt": byte2b64(self.serversalt),
        }
        return data

if __name__ == "__main__":
    try:
        UserClass("alice", "9165f8928421fada42e4609690f59c5b8f4aaebc35b5ce9b2acf32995d4d9f83")
    except UserExistsError as e:
        print(e)