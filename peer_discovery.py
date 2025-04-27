# PeerDiscovery.py
import socket
import json
import threading
import time
from typing import Dict, Callable

class PeerDiscovery:
    """
    Listens on UDP port 6000 for broadcast messages of format { "username": "name" }
    Maintains peers seen in last 900s, marks Online/Away based on last 10s
    """
    def __init__(self, port: int = 6000):
        self.port = port
        self.peers: Dict[str, dict] = {}         # username -> {ip, last_seen}
        self.running = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.callbacks: list[Callable[[dict], None]] = []

    def start(self, username: str):
        self.username = username
        self.running = True
        try:
            self.sock.bind(('', self.port))
            threading.Thread(target=self._listen_loop, daemon=True).start()
        except Exception as e:
            print(f"Error binding to port {self.port}: {e}")
            self.running = False

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except Exception as e:
            print(f"Error closing socket: {e}")

    def add_peer_callback(self, cb: Callable[[dict], None]):
        self.callbacks.append(cb)

    def _listen_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                msg = json.loads(data.decode())
                name = msg.get('username')
                ip = addr[0]  # Get IP from the socket address
                
                now = time.time()
                if name and name != self.username:
                    # Display detected user
                    print(f"\r{name} is online", end="", flush=True)
                    print("\n> ", end="", flush=True)
                    
                    # update record
                    self.peers[name] = {'ip': ip, 'last_seen': now}
                    
                    # remove stale peers (older than 15 minutes)
                    to_remove = [u for u, d in self.peers.items() if now - d['last_seen'] > 900]
                    for u in to_remove:
                        del self.peers[u]
                        
                    # notify callbacks
                    peers_with_status = self.get_peers()
                    for cb in self.callbacks:
                        cb(peers_with_status)
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"\rError in listener loop: {e}", end="", flush=True)
                print("\n> ", end="", flush=True)
                continue

    def get_peers(self) -> dict:
        now = time.time()
        result: dict = {}
        for name, d in self.peers.items():
            delta = now - d['last_seen']
            if delta <= 900:  # Only show peers seen in last 15 minutes
                status = '(Online)' if delta <= 10 else '(Away)'
                result[name] = {'ip': d['ip'], 'status': status}
        return result
