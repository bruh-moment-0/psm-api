#!/usr/bin/env python3
"""
Simple PSM Message API Test
Tests the basic message sending and retrieval functionality
"""

import requests
import json
import hashlib
import uuid

# API base URL
BASE_URL = "http://localhost:8000"

def test_send_message():
    """Test sending a message"""
    print("📤 Testing message sending...")
    
    # Create a test message
    message_data = {
        "messageid": str(uuid.uuid4()),
        "sender": "testuser",  # This user should exist in your users/ directory
        "sender_verify": "testclienthashed",  # This should match the user's clienthashed
        "reciever": "alice",
        "sender_pk": "testuser_public_key",
        "reciever_pk": "alice_public_key", 
        "shared_secret": "encrypted_shared_secret_here",
        "payload": "Hello Alice! This is a test message."
    }
    
    try:
        response = requests.post(f"{BASE_URL}/api/send", json=message_data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Message sent successfully!")
            print(f"   Message ID: {result['messageid']}")
            return result['messageid']
        else:
            print(f"❌ Failed to send message: {response.status_code}")
            print(f"   Response: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Error sending message: {str(e)}")
        return None

def test_get_inbox(username):
    """Test getting inbox messages for a user"""
    print(f"📥 Testing inbox retrieval for {username}...")
    
    try:
        response = requests.get(f"{BASE_URL}/api/messages/inbox/{username}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Inbox retrieved successfully!")
            print(f"   Found {result['count']} messages")
            
            for msg in result['messages']:
                print(f"   - From: {msg['sender']}, Content: {msg['payload'][:50]}...")
            
            return result['messages']
        else:
            print(f"❌ Failed to get inbox: {response.status_code}")
            print(f"   Response: {response.text}")
            return []
            
    except Exception as e:
        print(f"❌ Error getting inbox: {str(e)}")
        return []

def test_get_sent(username):
    """Test getting sent messages for a user"""
    print(f"📤 Testing sent messages retrieval for {username}...")
    
    try:
        response = requests.get(f"{BASE_URL}/api/messages/sent/{username}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Sent messages retrieved successfully!")
            print(f"   Found {result['count']} messages")
            
            for msg in result['messages']:
                print(f"   - To: {msg['reciever']}, Content: {msg['payload'][:50]}...")
            
            return result['messages']
        else:
            print(f"❌ Failed to get sent messages: {response.status_code}")
            print(f"   Response: {response.text}")
            return []
            
    except Exception as e:
        print(f"❌ Error getting sent messages: {str(e)}")
        return []

def test_get_specific_message(message_id):
    """Test getting a specific message by ID"""
    print(f"🔍 Testing specific message retrieval for ID: {message_id}...")
    
    try:
        response = requests.get(f"{BASE_URL}/api/messages/{message_id}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Message retrieved successfully!")
            print(f"   Sender: {result['message']['sender']}")
            print(f"   Receiver: {result['message']['reciever']}")
            print(f"   Content: {result['message']['payload']}")
            return result['message']
        else:
            print(f"❌ Failed to get message: {response.status_code}")
            print(f"   Response: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Error getting message: {str(e)}")
        return None

def main():
    """Run all tests"""
    print("🚀 Starting Simple PSM Message API Tests\n")
    print("=" * 50)
    
    # Test 1: Send a message
    message_id = test_send_message()
    
    if message_id:
        print("\n" + "=" * 50)
        
        # Test 2: Get inbox for receiver
        test_get_inbox("alice")
        
        print("\n" + "=" * 50)
        
        # Test 3: Get sent messages for sender
        test_get_sent("testuser")
        
        print("\n" + "=" * 50)
        
        # Test 4: Get specific message
        test_get_specific_message(message_id)
    
    print("\n" + "=" * 50)
    print("🏁 Tests completed!")

if __name__ == "__main__":
    main()
