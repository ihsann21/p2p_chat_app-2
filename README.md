# P2P Chat Application
CMP2204 Term Project Spring 2025

## System Overview

A peer-to-peer chat application that enables secure communication within a Local Area Network. The application consists of four main processes that work together to provide chat functionality.

## Core Processes

1. **Service Announcer**
   - Broadcasts user presence every 8 seconds
   - Uses UDP broadcast to 192.168.1.255
   - Sends username in JSON format
   - Port: 6000

2. **Peer Discovery**
   - Listens for UDP broadcasts on port 6000
   - Tracks peer presence and status
   - Maintains user status (Online/Away)
   - Shows users discovered in last 15 minutes

3. **Chat Initiator**
   - Handles outgoing messages
   - Supports secure chat with Diffie-Hellman
   - Uses TCP on port 6001
   - Manages message encryption

4. **Chat Responder**
   - Listens for incoming TCP connections
   - Handles message decryption
   - Maintains chat history
   - Port: 6001

## Features

- Automatic peer discovery in LAN
- User status tracking:
  - (Online): Seen in last 10 seconds
  - (Away): Not seen in last 10 seconds
  - Removed after 15 minutes of inactivity
- Secure messaging using Diffie-Hellman (p=19, g=2)
- Message history with timestamps
- Both encrypted and unencrypted chat options

## Requirements

- Python 3.8 or higher
- Network with UDP broadcast enabled
- Required Python packages (see requirements.txt)
- Local network (192.168.1.x)

## Setup

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the application:
   ```bash
   python main.py
   ```

## Usage

1. Start the application and enter your username
2. Available commands:
   - `help` - Show detailed help message
   - `users` or `list` - Show available peers
   - `chat <username>` - Start chat with peer
   - `history` - Show all chat history
   - `log <username>` - Show chat history with specific peer
   - `encrypt` - Toggle encryption for current chat
   - `quit` - Exit application

3. Chat Features:
   - Automatic user discovery
   - Real-time status updates
   - Secure chat option with key exchange
   - Message history logging
   - Timestamps for all messages

## Message Formats

1. Service Announcement (UDP):
   ```json
   {"username": "name", "ip": "ip_address"}
   ```

2. Secure Chat:
   ```json
   {"encrypted_message": "content", "username": "name"}
   ```

3. Regular Chat:
   ```json
   {"unencrypted_message": "content", "username": "name"}
   ```

4. Key Exchange:
   ```json
   {"key": "public_key"}
   ```

## Technical Details

- UDP Port: 6000 (Peer Discovery)
- TCP Port: 6001 (Chat)
- Broadcast IP: 192.168.1.255
- Broadcast Interval: 8 seconds
- Status Timeouts:
  - Online: <= 10 seconds
  - Away: > 10 seconds
  - Inactive: > 15 minutes
- Diffie-Hellman Parameters:
  - p = 19 (Prime)
  - g = 2 (Generator) 