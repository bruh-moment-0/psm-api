from fastapi import FastAPI, Request, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from dateutil.relativedelta import relativedelta
from pydantic import BaseModel
from data import *
import json
import datetime
import uuid
import os

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Message storage directory
MESSAGEDIR = os.path.join(BASEDIR, "messages")

# Create messages directory if it doesn't exist
if not os.path.exists(MESSAGEDIR):
    os.makedirs(MESSAGEDIR)

class Message(BaseModel):
    messageid: str
    sender: str
    sender_verify: str
    reciever: str
    sender_pk: str
    reciever_pk: str
    shared_secret: str
    payload: str

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