import socket
import json
import threading
import base64
import hashlib
import sys
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
        sys.stderr.write(f"Chat responder service started on port {self.port}\n")

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
                sys.stderr.write(f"Incoming connection from {addr[0]}\n")
                threading.Thread(target=self._handle_client, args=(client, addr), daemon=True).start()
            except:
                continue

    def _handle_client(self, client: socket.socket, addr):
        ts = datetime.now().isoformat()
        try:
            data = client.recv(4096)
            msg = json.loads(data.decode())
            ip = addr[0]

            if 'key' in msg:
                peer_pub = int(msg['key'])
                my_pub = pow(self.g, self.private_key, self.p)
                shared = pow(peer_pub, self.private_key, self.p)
                raw_secret = hashlib.sha256(str(shared).encode()).digest()
                fkey = base64.urlsafe_b64encode(raw_secret)
                self.dh_keys[ip] = Fernet(fkey)
                client.send(json.dumps({'key': str(my_pub)}).encode())
                sys.stderr.write(f"Key exchange with {ip} completed\n")

            elif 'encrypted_message' in msg:
                sender = msg.get('username', 'Unknown')
                self.ip_to_name[ip] = sender
                base64_token = msg['encrypted_message']
                try:
                    # Base64 kodunu çöz ve şifreli mesajı çöz
                    encrypted_bytes = base64.b64decode(base64_token)
                    content = self.dh_keys[ip].decrypt(encrypted_bytes).decode()
                    sys.stderr.write(f"Received encrypted message from {sender} ({ip})\n")
                except Exception as e:
                    # Log error to Network Log tab
                    sys.stderr.write(f"Decryption failed from {sender} ({ip}): {e}\n")
                    content = '[Decryption failed]'
                self._log_message(sender, content, False, True, ts)
                
                if self.message_callback:
                    self.message_callback(sender, content, True)

            elif 'unencrypted_message' in msg:
                sender = msg.get('username', 'Unknown')
                self.ip_to_name[ip] = sender  
                content = msg['unencrypted_message']
                sys.stderr.write(f"Received unencrypted message from {sender} ({ip})\n")
                self._log_message(sender, content, False, False, ts)
                
                if self.message_callback:
                    self.message_callback(sender, content, False)

        except Exception as e:
            # Log error to Network Log tab
            sys.stderr.write(f"Error handling client {addr[0]}: {e}\n")
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
