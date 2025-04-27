import socket
import json
import threading
import time
import sys
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
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception as e:
            print(f"Error creating UDP socket: {e}")
            sys.exit(1)
        self.callbacks: list[Callable[[dict], None]] = []
        # Kullanıcı bildirimlerini takip etmek için son görülme zamanları
        self.last_notification: Dict[str, float] = {}

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
                    # İlk kez kullanıcı keşfedildiğinde veya uzun süre (en az 60 saniye) sonra tekrar görüldüğünde bildirim yap
                    is_new_user = name not in self.peers
                    is_returning_user = name in self.last_notification and (now - self.last_notification[name]) > 60
                    
                    if is_new_user or is_returning_user:
                        # Sadece yeni veya uzun süre sonra tekrar görülen kullanıcıları bildir
                        print(f"\n{name} is online")
                        print("> ", end="", flush=True)
                        self.last_notification[name] = now
                    
                    # update record
                    self.peers[name] = {'ip': ip, 'last_seen': now}
                    
                    # remove stale peers (older than 15 minutes)
                    to_remove = [u for u, d in self.peers.items() if now - d['last_seen'] > 900]
                    for u in to_remove:
                        del self.peers[u]
                        if u in self.last_notification:
                            del self.last_notification[u]
                        
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
