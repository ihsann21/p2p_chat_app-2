import socket
import json
import threading
import base64
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet

class ChatResponder:
    """
    Listens on TCP port 6001 for incoming JSON messages:
    - Key exchange: { "key": "pub" }
    - Encrypted:    { "encrypted_message": "...", "username": "..." }
    - Plain:        { "unencrypted_message": "...", "username": "..." }
    Logs to chat_history.log and keeps in-memory history.
    """
    def __init__(self, username: str, port: int = 6001):
        self.username = username
        self.port = port
        self.running = False
        self.dh_keys: dict[str, Fernet] = {}  
        self.chat_log: dict[str, list] = {}   
        self.ip_to_name: dict[str, str] = {}  
        self.message_callback = None
        self.p, self.g = 19, 2
        self.private_key = 5
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        self.running = True
        self.server_socket.bind(('', self.port))
        self.server_socket.listen(5)
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self):
        self.running = False
        try:
            self.server_socket.close()
        except:
            pass
            
    def set_message_callback(self, callback):
        """Set callback to be called when a message is received"""
        self.message_callback = callback

    def _accept_loop(self):
        while self.running:
            try:
                client, addr = self.server_socket.accept()
                threading.Thread(target=self._handle_client, args=(client, addr), daemon=True).start()
            except:
                continue

    def _handle_client(self, client: socket.socket, addr):
        ts = datetime.now().isoformat()
        try:
            data = client.recv(4096)
            print(f"[Responder DEBUG] Received raw: {data!r} from {addr}")
            msg = json.loads(data.decode())
            ip = addr[0]

            if 'key' in msg:
                peer_pub = int(msg['key'])
                print(f"[Responder DEBUG] DH request from {ip}, peer_pub={peer_pub}")
                my_pub = pow(self.g, self.private_key, self.p)
                shared = pow(peer_pub, self.private_key, self.p)
                raw_secret = hashlib.sha256(str(shared).encode()).digest()
                fkey = base64.urlsafe_b64encode(raw_secret)
                self.dh_keys[ip] = Fernet(fkey)
                client.send(json.dumps({'key': str(my_pub)}).encode())

            elif 'encrypted_message' in msg:
                sender = msg.get('username', 'Unknown')
                self.ip_to_name[ip] = sender
                base64_token = msg['encrypted_message']
                try:
                    # Base64 kodunu çöz ve şifreli mesajı çöz
                    encrypted_bytes = base64.b64decode(base64_token)
                    content = self.dh_keys[ip].decrypt(encrypted_bytes).decode()
                except Exception as e:
                    print(f"Decryption failed: {e}")
                    content = '[Decryption failed]'
                self._log_message(sender, content, False, True, ts)
                
                if self.message_callback:
                    self.message_callback(sender, content, True)

            elif 'unencrypted_message' in msg:
                sender = msg.get('username', 'Unknown')
                self.ip_to_name[ip] = sender  
                content = msg['unencrypted_message']
                self._log_message(sender, content, False, False, ts)
                
                if self.message_callback:
                    self.message_callback(sender, content, False)

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client.close()

    def _log_message(self, sender: str, content: str, sent: bool, encrypted: bool, ts: str):
        """Log message to memory and file"""
        self.chat_log.setdefault(sender, []).append({
            'sent': sent,
            'content': content,
            'timestamp': ts,
            'encrypted': encrypted
        })
        with open('chat_history.log', 'a') as f:
            direction = 'SENT' if sent else 'RECEIVED'
            f.write(f"{ts},{sender},{self.username},{direction},{encrypted},{content}\n")

    def get_chat_log(self, peer: str):
        """Get chat history for a peer by username"""
        return self.chat_log.get(peer, [])
