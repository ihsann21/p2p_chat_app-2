import socket
import json
import base64
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
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((peer_ip, self.port))

            my_pub = pow(self.g, self.private_key, self.p)
            print(f"[Initiator DEBUG] Sending public key: {my_pub}")
            client.send(json.dumps({"key": str(my_pub)}).encode())

            raw = client.recv(4096)
            print(f"[Initiator DEBUG] Raw response: {raw!r}")
            resp = json.loads(raw.decode())

            if "key" in resp:
                peer_pub = int(resp["key"])
                print(f"[Initiator DEBUG] Received peer public key: {peer_pub}")
                shared = pow(peer_pub, self.private_key, self.p)
                raw_secret = hashlib.sha256(str(shared).encode()).digest()
                fkey = base64.urlsafe_b64encode(raw_secret)
                self.dh_keys[peer_ip] = Fernet(fkey)
                return True
        except Exception as e:
            print(f"Error during key exchange: {e}")
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

            self.chat_log.setdefault(peer_name, []).append({
                'sent': True,
                'content': message,
                'timestamp': ts,
                'encrypted': encrypted
            })
            with open('chat_history.log', 'a') as f:
                f.write(f"{ts},{self.username},{peer_name},{peer_ip},SENT,{encrypted},{message}\n")
        except Exception as e:
            print(f"Error sending message: {e}")

    def get_chat_log(self, peer_name: str):
        """Get chat log for a specific peer by name"""
        return self.chat_log.get(peer_name, [])
