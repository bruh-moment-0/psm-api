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