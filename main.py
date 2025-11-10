from fastapi import FastAPI, Header, Request, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from dateutil.relativedelta import relativedelta
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv
from typing import Optional
from data import *
from quantum import sign_obj_create, sign, verify, create_key_pair
import hashlib
import uuid
import time
import jwt
import os
import re

BASEDIR = os.path.abspath(os.path.dirname(__file__))
STATICDIR = os.path.join(BASEDIR, "static")
TEMPLATESDIR = os.path.join(BASEDIR, "templates")
ACCESS_TTL = 300 # 5 min

app = FastAPI()
app.mount("/static", StaticFiles(directory=STATICDIR), name="static")
templates = Jinja2Templates(directory=TEMPLATESDIR)

# env
load_dotenv(dotenv_path=DOTENV_PATH)
print("loaded .env from:", os.path.abspath(DOTENV_PATH))
ACCESS_KEY = os.getenv("ACCESS_KEY")
CONNECTION_PUBLIC_KEY_HEX = os.getenv("CONNECTION_PUBLIC_KEY")
CONNECTION_PRIVATE_KEY_HEX = os.getenv("CONNECTION_PRIVATE_KEY")
if not ACCESS_KEY: # generate once and keep in .env for persistence
    ACCESS_KEY = os.urandom(32).hex()
    with open(".env", "a") as f:
        f.write(f"\nACCESS_KEY={ACCESS_KEY}")
if (not CONNECTION_PUBLIC_KEY_HEX) or (not CONNECTION_PRIVATE_KEY_HEX):
    CONNECTION_PUBLIC_KEY, CONNECTION_PRIVATE_KEY = create_key_pair(sign_obj_create())
    with open(".env", "a") as f:
        f.write(f"\nCONNECTION_PUBLIC_KEY={CONNECTION_PUBLIC_KEY.hex()}")
        f.write(f"\nCONNECTION_PRIVATE_KEY={CONNECTION_PRIVATE_KEY.hex()}")
else:
    CONNECTION_PUBLIC_KEY = bytes.fromhex(CONNECTION_PUBLIC_KEY_HEX)
    CONNECTION_PRIVATE_KEY = bytes.fromhex(CONNECTION_PRIVATE_KEY_HEX)

SIGN_TOKEN_OBJ = sign_obj_create()
SIGN_CONNECTION_OBJ = sign_obj_create(CONNECTION_PRIVATE_KEY)

def now():
    return int(time.time())

# === Schemas ===
class MessageSendModel(BaseModel):
    messageid: str
    sender: str
    receiver: str
    sender_pk: str
    receiver_pk: str
    ciphertext: str
    payload_ciphertext: str
    payload_tag: str
    payload_salt: str
    payload_nonce: str
    sendertoken: str
    hkdfsalt: str

class MessageGetModel(BaseModel):
    messageid: str
    sendertoken: str

class MessageIDGENModel(BaseModel):
    sender: str
    sendertoken: str
    receiver: str
    update: bool

class UserClassModel(BaseModel):
    username: str
    publickey_kyber: str
    publickey_token: str
    publickey_connection: str

class TokenStart(BaseModel):
    username: str

class TokenFinish(BaseModel):
    username: str
    challenge_id: str
    signature: str

# === Helpers ===
@app.middleware("http")
async def capture_body_for_signature_verification(request: Request, call_next):
    # middleware to capture and store request body for signature verification
    # pydantic consumes the body, so we need to store it in request.state
    if request.method in ["POST", "PUT", "PATCH"]:
        body_bytes = await request.body()
        try:
            body_dict = json.loads(body_bytes) if body_bytes else {}
            request.state.body_dict = body_dict
        except json.JSONDecodeError:
            request.state.body_dict = {}
        # important: create new request with body since we consumed it
        async def receive():
            return {"type": "http.request", "body": body_bytes}
        request._receive = receive
    else:
        request.state.body_dict = {}
    response = await call_next(request)
    return response

def verify_connection_signature_header(request: Request, x_connection_signature: Optional[str], username: Optional[str] = None) -> bool: # pyright: ignore[reportReturnType]
    if not x_connection_signature:
        if username is None:
            return True
        error("missing_connection_signature", 400)
    if x_connection_signature == "None":
        return True
    if username is None:
        error("cannot_verify_signature_without_username", 400)
    user_file = os.path.join(USERDIR, f"{username}-V1.json")
    if not os.path.exists(user_file):
        error("user_not_found", 404)
    user_data = readjson(user_file)
    user_connection_pubkey = b642byte(user_data.get("publickey_connection")) # pyright: ignore[reportArgumentType]
    # reconstruct what was signed
    method = request.method
    path = request.url.path
    body_dict = getattr(request.state, "body_dict", {})
    sign_payload = {
        "method": method,
        "path": path,
        "body": body_dict
    }
    sign_payload_str = json.dumps(sign_payload, sort_keys=True, separators=(',', ':'))
    try:
        signature_bytes = b642byte(x_connection_signature) # pyright: ignore[reportArgumentType]
        is_valid = verify(
            SIGN_CONNECTION_OBJ, 
            str2byte(sign_payload_str), 
            signature_bytes, 
            user_connection_pubkey
        )
        if not is_valid:
            error("invalid_connection_signature", 403)
        return True
    except Exception as e:
        print(f"signature verification failed: {e}")
        error("signature_verification_failed", 403)

def signAccess(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "iat": now(),
        "exp": now() + ACCESS_TTL
    }
    return jwt.encode(payload, ACCESS_KEY, algorithm="HS256") # pyright: ignore[reportArgumentType]

def error(msg: str, code: int = 400):
    raise HTTPException(status_code=code, detail={"error": msg})

def cleanup_challenges(challenges: dict) -> dict:
    return {cid: info for cid, info in challenges.items() if info["exp"] >= now()} # drop expired

def verify_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, ACCESS_KEY, algorithms=["HS256"]) # pyright: ignore[reportArgumentType]
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def get_chat_hash(user1: str, user2: str) -> str:
    # order-independent hash
    sorted_pair = sorted([user1, user2])
    return hashlib.sha256("".join(sorted_pair).encode()).hexdigest()[:12]  # shorten if you want

def get_next_msg_id(sender: str, receiver: str, update: bool) -> str:
    chat_hash = get_chat_hash(sender, receiver)
    counter_file = os.path.join(MESSAGECOUNTERDIR, f"{chat_hash}-V1.json")
    if os.path.exists(counter_file):
        data = readjson(counter_file)
        counter = data.get("counter", 0)
    else:
        data = {
            "sender": sender,
            "receiver": receiver,
            "counter": 0
        }
        counter = 0
    if update:
        counter += 1
        data["counter"] = counter
        writejson(counter_file, data)
    return f"{chat_hash}-{counter}"

def usernameok(username):
    return (bool(username) and 3 <= len(username) <= 32 and not bool(re.search(r'[^a-zA-Z0-9_-]', username)))

# === Endpoints ===
@app.get("/", response_class=HTMLResponse)
async def homeUI(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "version": VERSION})

@app.post("/details-submit")
async def submitUI(username: str = Form(...)):
    filepath = os.path.join(USERDIR, f"{username}-V1.json")
    if not os.path.exists(filepath):
        return RedirectResponse(url="/?error=USER_NOT_FOUND", status_code=303)
    data = readjson(filepath)
    if not data:
        return RedirectResponse(url=f"/?error=USER_DATA_BROKEN", status_code=303)
    return RedirectResponse(url=f"/user/{data['username']}", status_code=302)

@app.get("/user/{username}", response_class=HTMLResponse)
async def showUserUI(request: Request, username: str):
    filepath = os.path.join(USERDIR, f"{username}-V1.json")
    data = readjson(filepath)
    ver = data["ver"]
    usertype = data["type"]
    creation = data["creation"]
    publickey_kyber = data["publickey_kyber"]
    key_wrapped = "\n".join([publickey_kyber[i:i+64] for i in range(0, len(publickey_kyber), 64)])
    dt = datetime.datetime.fromtimestamp(creation, datetime.timezone.utc)
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    age = relativedelta(now_dt, dt)
    agestr = f"{age.years}y {age.months}m {age.days}d {age.hours}h {age.minutes}m {age.seconds}s"
    info = f"ver: {ver}\ntype: {usertype}\ncreation {dt.strftime('%d-%m-%Y %H:%M:%S UTC')} (DD/MM/YYYY hh:mm:ss)\n"
    info += f"account age: {agestr}\npublic key:\n{key_wrapped}"
    return templates.TemplateResponse("user.html", {"request": request, "title": username, "info": info})

@app.post("/auth/register")
async def register(x: UserClassModel, request: Request, x_connection_signature: Optional[str] = Header(None)):
    verify_connection_signature_header(request, x_connection_signature, None)
    if usernameok(x.username):
        uf = os.path.join(USERDIR, f"{x.username}-V1.json")
        if os.path.exists(uf):
            error("user_exists", 400)
        if len(x.publickey_kyber) != 1580: # public length for kyber 768
            print(len(x.publickey_kyber))
            error("bad_kyber_method", 400)
        writejson(uf, UserClass(x.username, x.publickey_kyber, x.publickey_token, x.publickey_connection).out())
        return {"ok": True}
    else:
        error("bad_username", 400) # fixed http num

@app.post("/auth/challenge")
async def login_start(x: TokenStart, request: Request, x_connection_signature: Optional[str] = Header(None)):
    verify_connection_signature_header(request, x_connection_signature, x.username)
    uf = os.path.join(USERDIR, f"{x.username}-V1.json")
    if not os.path.exists(uf):
        error("user_not_found", 404)
    fp = os.path.join(USERDIR, f"{x.username}_challenge.json")
    data = readjson(fp)
    challenges = cleanup_challenges(data.get("challenges", {}))
    cid = str(uuid.uuid4())
    val = os.urandom(32).hex()
    challenges[cid] = {"username": x.username, "value": val, "exp": now() + 60}
    writejson(fp, {"challenges": challenges})
    return {"challenge_id": cid, "challenge": val}

@app.post("/auth/respond")
def login_finish(x: TokenFinish, request: Request, x_connection_signature: Optional[str] = Header(None)):
    verify_connection_signature_header(request, x_connection_signature, x.username)
    fp = os.path.join(USERDIR, f"{x.username}_challenge.json")
    data = readjson(fp)
    challenges = cleanup_challenges(data.get("challenges", {}))
    if x.challenge_id not in challenges:
        error("challenge_invalid", 401)
    ch = challenges[x.challenge_id]
    if ch["username"] != x.username:
        error("challenge_invalid", 401)
    uf = os.path.join(USERDIR, f"{x.username}-V1.json")
    pub = b642byte(readjson(uf)["publickey_token"])
    sign_valid = verify(SIGN_TOKEN_OBJ, ch["value"].encode(), b642byte(x.signature), pub)
    if not sign_valid:
        error("sig_fail", 401)
    challenges.pop(x.challenge_id, None)
    writejson(fp, {"challenges": challenges})
    tok = signAccess(x.username)
    return {"access_token": tok, "token_type": "bearer"}

@app.get("/auth/protected")
async def protected(req: Request):
    auth = req.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        error("missing_token", 401)
    token = auth.split(" ", 1)[1] # pyright: ignore[reportOptionalMemberAccess]
    payload = verify_token(token)
    if not payload:
        error("token_invalid_or_expired", 401)
    return {"ok": True, "user": payload["sub"], "exp": payload["exp"]} # pyright: ignore[reportOptionalSubscript]
    # exp payload is important for client-side to remind the client to auto request new tokens

@app.post("/api/message/send")
async def sendMessage(msg: MessageSendModel, request: Request, x_connection_signature: Optional[str] = Header(None)):
    verify_connection_signature_header(request, x_connection_signature, msg.sender)
    try:
        senderfp = os.path.join(USERDIR, f"{msg.sender}-V1.json")
        if not os.path.exists(senderfp):
            error("sender_not_found", 404)
        payload = verify_token(msg.sendertoken)
        if not payload or payload["sub"] != msg.sender:
            error("token_invalid_or_expired", 401)
        receiverfp = os.path.join(USERDIR, f"{msg.receiver}-V1.json")
        if not os.path.exists(receiverfp):
            error("receiver_not_found", 404)
        messagefp = os.path.join(BASEMESSAGEDIR, f"{msg.messageid}-msg-V1.json")
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        messagedata = {
            "messageid": msg.messageid,
            "sender": msg.sender,
            "receiver": msg.receiver,
            "tokenexp": payload["exp"], # pyright: ignore[reportOptionalSubscript]
            "sender_pk": msg.sender_pk,
            "receiver_pk": msg.receiver_pk,
            "ciphertext": msg.ciphertext,
            "payload_ciphertext": msg.payload_ciphertext,
            "payload_tag": msg.payload_tag,
            "payload_salt": msg.payload_salt,
            "payload_nonce": msg.payload_nonce,
            "hkdfsalt": msg.hkdfsalt,
            "timestamp": timestamp
        }
        writejson(messagefp, messagedata)
        return {"ok": True, "tokenexp": payload["exp"], "messageid": msg.messageid, "timestamp": timestamp} # pyright: ignore[reportOptionalSubscript]
    except Exception:
        error("failed_to_send_message", 500)

@app.get("/api/message/get/{messageid}")
async def getMessage(messageid: str, sendertoken: str):
    payload = verify_token(sendertoken)
    if not payload:
        error("token_invalid_or_expired", 401)
    messagefp = os.path.join(BASEMESSAGEDIR, f"{messageid}-msg-V1.json")
    if not os.path.exists(messagefp):
        error("message_not_found", 404)
    messagedata = readjson(messagefp)
    if payload["sub"] not in [messagedata.get("sender"), messagedata.get("receiver")]: # pyright: ignore[reportOptionalSubscript]
        error("unauthorized_access", 403)
    return {"ok": True, "tokenexp": payload["exp"], "message": messagedata} # pyright: ignore[reportOptionalSubscript]

@app.post("/api/message/genid")
async def genID(x: MessageIDGENModel, request: Request, x_connection_signature: Optional[str] = Header(None)): # pyright: ignore[reportArgumentType]
    verify_connection_signature_header(request, x_connection_signature, x.sender)
    payload = verify_token(x.sendertoken)
    if not payload or payload["sub"] != x.sender:
        error("token_invalid_or_expired", 401)
    return {"ok": True, "tokenexp": payload["exp"], "msgid": get_next_msg_id(x.sender, x.receiver, x.update)} # pyright: ignore[reportOptionalSubscript]

@app.get("/api/user/{username}")
async def getUser(request: Request, username: str):
    filepath = os.path.join(USERDIR, f"{username}-V1.json")
    if not os.path.exists(filepath):
        error("user_not_found", 404)
    data = readjson(filepath)
    if not data:
        error("user_data_broken", 500)
    ver = data["ver"]
    usertype = data["type"]
    creation = data["creation"]
    publickey_kyber = data["publickey_kyber"]
    dt = datetime.datetime.fromtimestamp(creation, datetime.timezone.utc)
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    age = relativedelta(now_dt, dt)
    agestr = f"{age.years}y {age.months}m {age.days}d {age.hours}h {age.minutes}m {age.seconds}s"
    data = {
        "ver": ver,
        "usertype": usertype,
        "creation": creation,
        "publickey_kyber": publickey_kyber,
        "agestr": agestr
    }
    return {"ok": True, "data": data}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)