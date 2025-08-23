from fastapi import FastAPI, HTTPException, Request
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from pydantic import BaseModel
from dotenv import load_dotenv
from data import *
import jwt
import time
import os
import uuid

# === Setup ===
load_dotenv()
app = FastAPI()

ACCESS_KEY = os.getenv("ACCESS_KEY")
if not ACCESS_KEY:
    # generate once and keep in .env for persistence
    ACCESS_KEY = os.urandom(32).hex()
    with open(".env", "a") as f:
        f.write(f"\nACCESS_KEY={ACCESS_KEY}\n")

ACCESS_TTL = 900  # 15 min

def now():
    return int(time.time())

# === Schemas ===
class RegisterIn(BaseModel):
    username: str
    publickey: str

class LoginStartIn(BaseModel):
    username: str

class LoginFinishIn(BaseModel):
    username: str
    challenge_id: str
    signature: str

# === Helpers ===
def signAccess(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "iat": now(),
        "exp": now() + ACCESS_TTL
    }
    return jwt.encode(payload, ACCESS_KEY, algorithm="HS256")

def error(msg: str, code: int = 400):
    raise HTTPException(status_code=code, detail={"error": msg})

def cleanup_challenges(challenges: dict) -> dict:
    # drop expired
    return {cid: info for cid, info in challenges.items() if info["exp"] >= now()}

# === Endpoints ===
@app.post("/auth/register")
def register(x: RegisterIn):
    uf = os.path.join(USERDIR, f"{x.username}-V1.json")
    if os.path.exists(uf):
        error("user_exists", 400)
    writejson(uf, {"username": x.username, "publickey": x.publickey})
    return {"ok": True}

@app.post("/auth/challenge")
def login_start(x: LoginStartIn):
    uf = os.path.join(USERDIR, f"{x.username}-V1.json")
    if not os.path.exists(uf):
        error("user_not_found", 404)
    # load challenge file
    fp = os.path.join(USERDIR, f"{x.username}_challenge.json")
    data = readjson(fp)
    challenges = cleanup_challenges(data.get("challenges", {}))
    # generate new challenge
    cid = str(uuid.uuid4())
    val = os.urandom(32).hex()
    challenges[cid] = {"username": x.username, "value": val, "exp": now() + 60}
    writejson(fp, {"challenges": challenges})
    return {"challenge_id": cid, "challenge": val}

@app.post("/auth/respond")
def login_finish(x: LoginFinishIn):
    # find challenge file
    fp = os.path.join(USERDIR, f"{x.username}_challenge.json")
    data = readjson(fp)
    challenges = cleanup_challenges(data.get("challenges", {}))
    if x.challenge_id not in challenges:
        error("challenge_invalid", 401)
    ch = challenges[x.challenge_id]
    if ch["username"] != x.username:
        error("challenge_invalid", 401)
    # verify signature
    uf = os.path.join(USERDIR, f"{x.username}-V1.json")
    pub = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(readjson(uf)["publickey"])
    )
    try:
        pub.verify(bytes.fromhex(x.signature), ch["value"].encode())
    except InvalidSignature:
        error("sig_fail", 401)
    # remove used challenge
    challenges.pop(x.challenge_id, None)
    writejson(fp, {"challenges": challenges})
    # issue access token
    tok = signAccess(x.username)
    return {"access_token": tok, "token_type": "bearer"}

@app.get("/protected")
def protected(req: Request):
    auth = req.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        error("missing_token", 401)
    token = auth.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, ACCESS_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        error("token_expired", 401)
    except jwt.InvalidTokenError:
        error("token_invalid", 401)
    return {"ok": True, "user": payload["sub"], "exp": payload["exp"]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)