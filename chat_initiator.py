import socket
import json
import base64
import sys
from datetime import datetime
import hashlib
from cryptography.fernet import Fernet

class ChatInitiator:
    def __init__(self, username: str, port: int = 6001):
        self.username = username
        self.port = port
        self.dh_keys: dict[str, Fernet] = {}   
        self.chat_log: dict[str, list] = {}    
        self.ip_to_name: dict[str, str] = {}   
        self.name_to_ip: dict[str, str] = {}  
        self.p: int = 19                       
        self.g: int = 2                        
        self.private_key: int = 6

    def initiate_secure_chat(self, peer_ip: str) -> bool:
        """
        Perform Diffie-Hellman key exchange with peer at peer_ip.
        """
        sys.stderr.write(f"Initiating secure chat with {peer_ip}...\n")
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((peer_ip, self.port))

            my_pub = pow(self.g, self.private_key, self.p)
            client.send(json.dumps({"key": str(my_pub)}).encode())

            raw = client.recv(4096)
            resp = json.loads(raw.decode())

            if "key" in resp:
                peer_pub = int(resp["key"])
                shared = pow(peer_pub, self.private_key, self.p)
                raw_secret = hashlib.sha256(str(shared).encode()).digest()
                fkey = base64.urlsafe_b64encode(raw_secret)
                self.dh_keys[peer_ip] = Fernet(fkey)
                sys.stderr.write(f"Secure chat established with {peer_ip}\n")
                return True
        except Exception as e:
            # Log error to Network Log tab
            sys.stderr.write(f"Error during key exchange with {peer_ip}: {e}\n")
        finally:
            try:
                client.close()
            except:
                pass
        return False

    def send_message(self, peer_name: str, message: str, peer_ip: str, encrypted: bool = False):
        """
        Send a message (encrypted or plain) to peer_ip.
        Appends to in-memory and file log.
        """
        ts = datetime.now().isoformat()
        encryption_status = "encrypted" if encrypted else "unencrypted"
        sys.stderr.write(f"Sending {encryption_status} message to {peer_name} ({peer_ip})\n")
        
        self.name_to_ip[peer_name] = peer_ip
        self.ip_to_name[peer_ip] = peer_name
        
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((peer_ip, self.port))

            if encrypted and peer_ip in self.dh_keys:
                encrypted_bytes = self.dh_keys[peer_ip].encrypt(message.encode())
                base64_token = base64.b64encode(encrypted_bytes).decode()
                payload = {"encrypted_message": base64_token, "username": self.username}
            else:
                payload = {"unencrypted_message": message, "username": self.username}

            client.send(json.dumps(payload).encode())
            client.close()
            sys.stderr.write(f"Message sent successfully to {peer_name}\n")

            self.chat_log.setdefault(peer_name, []).append({
                'sent': True,
                'content': message,
                'timestamp': ts,
                'encrypted': encrypted
            })
            with open('chat_history.log', 'a') as f:
                f.write(f"{ts},{self.username},{peer_name},{peer_ip},SENT,{encrypted},{message}\n")
        except Exception as e:
            # Log error to Network Log tab
            sys.stderr.write(f"Error sending message to {peer_name} ({peer_ip}): {e}\n")

    def get_chat_log(self, peer_name: str):
        """Get chat log for a specific peer by name"""
        return self.chat_log.get(peer_name, [])
