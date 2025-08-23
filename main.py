from fastapi import FastAPI, Request, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from dateutil.relativedelta import relativedelta
from pydantic import BaseModel
from dotenv import load_dotenv
from data import *
import jwt
import time
import os
import uuid

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# auth settings
load_dotenv(dotenv_path=DOTENV_PATH)
ACCESS_KEY = os.getenv("ACCESS_KEY")
if not ACCESS_KEY: # generate once and keep in .env for persistence
    ACCESS_KEY = os.urandom(32).hex()
    with open(".env", "a") as f:
        f.write(f"\nACCESS_KEY={ACCESS_KEY}\n")
ACCESS_TTL = 900 # 15 min

def now():
    return int(time.time())

# === Schemas ===
class Message(BaseModel):
    messageid: str
    sender: str
    sender_verify: str
    reciever: str
    sender_pk: str
    reciever_pk: str
    shared_secret: str
    payload: str

class UserClassModel(BaseModel):
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
    return jwt.encode(payload, ACCESS_KEY, algorithm="HS256") # pyright: ignore[reportArgumentType]

def error(msg: str, code: int = 400):
    raise HTTPException(status_code=code, detail={"error": msg})

def cleanup_challenges(challenges: dict) -> dict:
    return {cid: info for cid, info in challenges.items() if info["exp"] >= now()} # drop expired

# === Endpoints ===
@app.get("/", response_class=HTMLResponse)
def homeUI(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/details-submit")
async def submitUI(username: str = Form(...)):
    filepath = os.path.join(USERDIR, f"{username}-V1.json")
    if not os.path.exists(filepath):
        return RedirectResponse(url=f"/?error=USER_NOT_FOUND", status_code=302)
    data = readjson(filepath)
    if not data:
        return RedirectResponse(url=f"/?error=USER_DATA_BROKEN", status_code=302)
    return RedirectResponse(url=f"/user/{data['username']}", status_code=302)

@app.get("/user/{username}", response_class=HTMLResponse)
def showUserUI(request: Request, username: str):
    filepath = os.path.join(USERDIR, f"{username}-V1.json")
    data = readjson(filepath)
    ver = data["ver"]
    usertype = data["type"]
    creation = data["creation"]
    publickey = data["publickey"]
    dt = datetime.datetime.fromtimestamp(creation, datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    age = relativedelta(now, dt)
    agestr = f"{age.years}y {age.months}m {age.days}d {age.hours}h {age.minutes}m {age.seconds}s"
    info = f"ver: {ver}\ntype: {usertype}\ncreation {dt.strftime('%d-%m-%Y %H:%M:%S UTC')} (DD/MM/YYYY hh:mm:ss)\n"
    info += f"account age: {agestr}\npublic key: {publickey}"
    return templates.TemplateResponse("user.html", {"request": request, "title": username, "info": info})

@app.post("/auth/register")
def register(x: UserClassModel):
    uf = os.path.join(USERDIR, f"{x.username}-V1.json")
    if os.path.exists(uf):
        error("user_exists", 400)
    writejson(uf, UserClass(x.username, x.publickey))
    return {"ok": True}

@app.post("/auth/challenge")
def login_start(x: LoginStartIn):
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
def login_finish(x: LoginFinishIn):
    fp = os.path.join(USERDIR, f"{x.username}_challenge.json")
    data = readjson(fp)
    challenges = cleanup_challenges(data.get("challenges", {}))
    if x.challenge_id not in challenges:
        error("challenge_invalid", 401)
    ch = challenges[x.challenge_id]
    if ch["username"] != x.username:
        error("challenge_invalid", 401)
    uf = os.path.join(USERDIR, f"{x.username}-V1.json")
    pub = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(readjson(uf)["publickey"])
    )
    try:
        pub.verify(bytes.fromhex(x.signature), ch["value"].encode())
    except InvalidSignature:
        error("sig_fail", 401)
    challenges.pop(x.challenge_id, None)
    writejson(fp, {"challenges": challenges})
    tok = signAccess(x.username)
    return {"access_token": tok, "token_type": "bearer"}

@app.get("/protected")
def protected(req: Request):
    auth = req.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        error("missing_token", 401)
    token = auth.split(" ", 1)[1] # pyright: ignore[reportOptionalMemberAccess]
    try:
        payload = jwt.decode(token, ACCESS_KEY, algorithms=["HS256"]) # pyright: ignore[reportArgumentType]
    except jwt.ExpiredSignatureError:
        error("token_expired", 401)
    except jwt.InvalidTokenError:
        error("token_invalid", 401)
    return {"ok": True, "user": payload["sub"], "exp": payload["exp"]} # pyright: ignore[reportPossiblyUnboundVariable]








# bellow is AI generated code to be further refined.

# API endpoint to send a message
@app.post("/api/send")
def sendMessage(msg: Message):
    try:
        # 1. Verify sender exists and password hash matches
        sender_filepath = os.path.join(USERDIR, f"{msg.sender}-V1.json")
        if not os.path.exists(sender_filepath):
            raise HTTPException(status_code=404, detail="Sender not found")
        
        sender_data = readjson(sender_filepath)
        
        # Check if sender_verify matches the stored password hash
        if sender_data.get("clienthashed") != msg.sender_verify:
            raise HTTPException(status_code=401, detail="Invalid sender verification")
        
        # 2. Store message in JSON file
        message_filepath = os.path.join(MESSAGEDIR, f"{msg.messageid}.json")
        
        message_data = {
            "messageid": msg.messageid,
            "sender": msg.sender,
            "sender_verify": msg.sender_verify,
            "reciever": msg.reciever,
            "sender_pk": msg.sender_pk,
            "reciever_pk": msg.reciever_pk,
            "shared_secret": msg.shared_secret,
            "payload": msg.payload,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        
        writejson(message_filepath, message_data)
        
        return {"status": "success", "message": "Message sent and stored!", "messageid": msg.messageid}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send message: {str(e)}")

# API endpoint to get messages for a user (inbox)
@app.get("/api/messages/inbox/{username}")
def getInbox(username: str):
    try:
        inbox_messages = []
        
        # Read all message files in the messages directory
        for filename in os.listdir(MESSAGEDIR):
            if filename.endswith('.json'):
                message_filepath = os.path.join(MESSAGEDIR, filename)
                message_data = readjson(message_filepath)
                
                # Check if this message is for the user
                if message_data.get("reciever") == username:
                    inbox_messages.append(message_data)
        
        # Sort by timestamp (newest first)
        inbox_messages.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        return {
            "status": "success",
            "messages": inbox_messages,
            "count": len(inbox_messages)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get inbox: {str(e)}")

# API endpoint to get messages sent by a user
@app.get("/api/messages/sent/{username}")
def getSent(username: str):
    try:
        sent_messages = []
        
        # Read all message files in the messages directory
        for filename in os.listdir(MESSAGEDIR):
            if filename.endswith('.json'):
                message_filepath = os.path.join(MESSAGEDIR, filename)
                message_data = readjson(message_filepath)
                
                # Check if this message was sent by the user
                if message_data.get("sender") == username:
                    sent_messages.append(message_data)
        
        # Sort by timestamp (newest first)
        sent_messages.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        return {
            "status": "success",
            "messages": sent_messages,
            "count": len(sent_messages)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get sent messages: {str(e)}")

# API endpoint to get a specific message by ID
@app.get("/api/messages/{messageid}")
def getMessage(messageid: str):
    try:
        message_filepath = os.path.join(MESSAGEDIR, f"{messageid}.json")
        
        if not os.path.exists(message_filepath):
            raise HTTPException(status_code=404, detail="Message not found")
        
        message_data = readjson(message_filepath)
        
        return {
            "status": "success",
            "message": message_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get message: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)