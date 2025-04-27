import socket
import json
import threading
import time
import ipaddress
import netifaces
import sys

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
        self.broadcast_interval = 8  # Fixed interval of 8 seconds

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
            start_time = time.time()
            message = {"username": self.username}
            try:
                self.sock.sendto(json.dumps(message).encode(), (self.broadcast_ip, self.port))
                # Don't log our own broadcasts - they're confusing the user
                # Only peer_discovery will log OTHER users coming online
            except Exception as e:
                # Log errors to Network Log tab only (not terminal)
                sys.stderr.write(f"Error broadcasting presence: {e}\n")
            
            # Calculate precise sleep time to maintain exact 8-second intervals
            elapsed = time.time() - start_time
            sleep_time = max(0, self.broadcast_interval - elapsed)
            time.sleep(sleep_time)
