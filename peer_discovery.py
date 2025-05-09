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
            # Log to Network Log tab
            sys.stderr.write(f"Error creating UDP socket: {e}\n")
            sys.exit(1)
        self.callbacks: list[Callable[[dict], None]] = []
        # Kullanıcı bildirimlerini takip etmek için son görülme zamanları
        self.last_notification: Dict[str, float] = {}
        # Yeni kullanıcı keşfedildiğinde bildirim vermek için
        self.new_users = set()
        # Set threshold to 4 seconds to ensure we catch every 8-second broadcast
        self.notification_threshold = 4  # Reduced from 8 to ensure we catch every broadcast

    def start(self, username: str):
        self.username = username
        self.running = True
        try:
            self.sock.bind(('', self.port))
            threading.Thread(target=self._listen_loop, daemon=True).start()
            # Sessiz bildirim için ayrı bir thread
            threading.Thread(target=self._notification_loop, daemon=True).start()
            sys.stderr.write(f"Peer discovery service started for {username}\n")
        except Exception as e:
            # Log to Network Log tab
            sys.stderr.write(f"Error binding to port {self.port}: {e}\n")
            self.running = False

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except Exception as e:
            # Log to Network Log tab
            sys.stderr.write(f"Error closing socket: {e}\n")

    def add_peer_callback(self, cb: Callable[[dict], None]):
        self.callbacks.append(cb)

    def _notification_loop(self):
        """Kullanıcı yazmaktayken kesintiye uğratmadan bildirimleri gösterir"""
        while self.running:
            time.sleep(1)  # Check more frequently (every 1 second)
            if self.new_users:
                # Show notification for other users coming online
                if len(self.new_users) == 1:
                    user = self.new_users.pop()
                    sys.stderr.write(f"{user} çevrimiçi oldu\n")
                else:
                    users = ", ".join(self.new_users)
                    self.new_users.clear()
                    sys.stderr.write(f"Şu kullanıcılar çevrimiçi oldu: {users}\n")

    def _listen_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                msg = json.loads(data.decode())
                name = msg.get('username')
                ip = addr[0]  # Get IP from the socket address
                
                now = time.time()
                if name and name != self.username:
                    # Always treat each message as if it needs a notification
                    # This ensures we get notifications for every broadcast (8 seconds)
                    self.new_users.add(name)
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
                # Log to Network Log tab
                sys.stderr.write(f"[HATA] Dinleme döngüsünde hata: {e}\n")
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
