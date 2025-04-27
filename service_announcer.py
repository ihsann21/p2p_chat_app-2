import socket
import json
import threading
import time
import ipaddress
import netifaces

class ServiceAnnouncer:
    """
    Broadcasts the user presence every 8 seconds on UDP port 6000 to 192.168.1.255
    Message format: { "username": "name" }
    """
    def __init__(self, port: int = 6000):
        self.port = port
        self.broadcast_ip = '172.20.10.15' 
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.running = False

    def start(self, username: str):
        self.username = username
        self.running = True
        threading.Thread(target=self._broadcast_loop, daemon=True).start()

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except:
            pass

    def _broadcast_loop(self):
        while self.running:
            message = {"username": self.username}
            try:
                self.sock.sendto(json.dumps(message).encode(), (self.broadcast_ip, self.port))
            except Exception as e:
                print(f"Error broadcasting presence: {e}")
            time.sleep(8)
