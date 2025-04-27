import os
import sys
import time
import readline  # Kullanıcı girişini koruma için
from datetime import datetime
from peer_discovery import PeerDiscovery
from service_announcer import ServiceAnnouncer
from chat_responder import ChatResponder
from chat_initiator import ChatInitiator

class ChatApplication:
    def __init__(self):
        self.username = input("Enter your username: ")
        
        print("Initializing application...")
        
        try:
            # Initialize all processes
            self.peer_discovery = PeerDiscovery()
            self.service_announcer = ServiceAnnouncer()
            self.chat_responder = ChatResponder(self.username)
            self.chat_initiator = ChatInitiator(self.username)
            
            self.peers = {}
            self.current_chat = None
            self.encryption_enabled = False
        except Exception as e:
            print(f"Error during initialization: {e}")
            sys.exit(1)
        
    def start(self):
        """Start the chat application"""
        # Start all processes
        print("Starting peer discovery service...")
        self.peer_discovery.start(self.username)
        
        print("Starting service announcer...")
        self.service_announcer.start(self.username)
        
        print("Starting chat responder...")
        self.chat_responder.start()
        
        # Setup callbacks
        self.peer_discovery.add_peer_callback(self._on_peers_update)
        self.chat_responder.set_message_callback(self._on_message_received)
        
        print(f"\nWelcome {self.username}!")
        self._print_brief_help()
        
        try:
            # Clear input buffer for clean prompt
            sys.stdin.flush()
            
            while True:
                try:
                    # readline modülü girilen metni korur
                    command = input("\n> ").strip()
                    
                    # Komut girişi için fazladan yeni satır
                    print("", end="")
                    
                    if command == "":
                        continue
                        
                    if command == "help":
                        self._print_detailed_help()
                        
                    elif command == "list" or command == "users":
                        self._list_peers()
                        
                    elif command.startswith("chat "):
                        peer = command[5:].strip()
                        self._start_chat(peer)
                        
                    elif command == "history":
                        self._show_full_history()
                        
                    elif command.startswith("log "):
                        peer = command[4:].strip()
                        self._show_chat_log(peer)
                        
                    elif command == "encrypt":
                        self._toggle_encryption()
                        
                    elif command == "quit":
                        break
                        
                    elif self.current_chat:
                        self._send_message(command)
                        
                    else:
                        print("Unknown command. Type 'help' for available commands.")
                
                except KeyboardInterrupt:
                    # Ctrl+C ile komut girişini iptal et, programı değil
                    print("\nCommand canceled")
                    continue
                        
        except KeyboardInterrupt:
            print("\nShutting down application...")
            
        finally:
            print("Closing connections...")
            self.peer_discovery.stop()
            self.service_announcer.stop()
            self.chat_responder.stop()
            print("Application safely closed.")
    
    def _print_brief_help(self):
        """Print brief help message at startup"""
        print("\nAvailable commands:")
        print("  help     - Show detailed help message")
        print("  users    - List available peers")
        print("  chat <username> - Start chat with peer")
        print("  history  - Show complete chat history")
        print("  log <username>  - Show chat history with peer")
        print("  encrypt  - Toggle encryption for current chat")
        print("  quit     - Exit application")
        print("\nWhen in chat:")
        print("  Just type your message and press enter to send")
        print("  Use /back to return to main menu")
        print("\nType 'help' for more detailed information.")

    def _print_detailed_help(self):
        """Print detailed help message with usage instructions"""
        print("\nP2P Chat Application Help")
        print("========================")
        
        print("\nMain Commands:")
        print("  users or list")
        print("    Shows all users discovered in last 15 minutes")
        print("    Shows status: (Online) if seen in last 10 seconds")
        print("                 (Away) if not seen in last 10 seconds")
        
        print("\n  chat <username>")
        print("    Starts a chat session with specified user")
        print("    You will be asked if you want secure (encrypted) chat")
        print("    Example: > chat alice")
        
        print("\n  history")
        print("    Shows complete chat history with all users")
        print("    Includes timestamps and encryption status")
        
        print("\n  log <username>")
        print("    Shows chat history with specific user")
        print("    Example: > log bob")
        
        print("\n  encrypt")
        print("    Toggles encryption for current chat")
        print("    Uses Diffie-Hellman key exchange for security")
        
        print("\nChat Mode:")
        print("  - Messages are automatically logged")
        print("  - Encrypted messages are marked as [Encrypted]")
        print("  - Use /back to return to main menu")

    def _show_full_history(self):
        """Show complete chat history with all users"""
        all_messages = []
        
        # Collect messages from both responder and initiator
        for peer in set(self.chat_responder.chat_log.keys()) | set(self.chat_initiator.chat_log.keys()):
            responder_log = self.chat_responder.get_chat_log(peer)
            initiator_log = self.chat_initiator.get_chat_log(peer)
            all_messages.extend((msg, peer) for msg in responder_log + initiator_log)
        
        if not all_messages:
            print("\nNo chat history")
            return
            
        # Sort by timestamp
        all_messages.sort(key=lambda x: x[0]['timestamp'])
        
        print("\nComplete Chat History:")
        for msg, peer in all_messages:
            prefix = "You:" if msg['sent'] else f"{peer}:"
            timestamp = datetime.fromisoformat(msg['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
            encrypted = "[Encrypted] " if msg['encrypted'] else ""
            print(f"[{timestamp}] {prefix} {encrypted}{msg['content']}")

    def _show_chat_log(self, peer: str):
        """Show chat history with a specific peer"""
        # Get chat logs from both responder and initiator
        responder_log = self.chat_responder.get_chat_log(peer)
        initiator_log = self.chat_initiator.get_chat_log(peer)
        
        # Combine and sort logs by timestamp
        combined_log = responder_log + initiator_log
        combined_log.sort(key=lambda x: x['timestamp'])
        
        if not combined_log:
            print(f"\nNo chat history with {peer}")
            return
            
        print(f"\nChat history with {peer}:")
        for msg in combined_log:
            prefix = "You:" if msg['sent'] else f"{peer}:"
            timestamp = datetime.fromisoformat(msg['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
            encrypted = "[Encrypted] " if msg['encrypted'] else ""
            print(f"[{timestamp}] {prefix} {encrypted}{msg['content']}")
        
    def _list_peers(self):
        """List available peers with their status"""
        peers = self.peer_discovery.get_peers()
        self.peers = peers
        
        if not peers:
            print("No peers found")
        else:
            print("\nAvailable peers:")
            for username, data in peers.items():
                print(f"  - {username} {data['status']}")
                
    def _start_chat(self, peer: str):
        """Start chat with peer"""
        if peer not in self.peers:
            print(f"Peer {peer} not found")
            return
            
        self.current_chat = peer
        peer_data = self.peers[peer]
        
        print(f"\nStarting chat with {peer}")
        
        # Ask for secure chat
        secure = input("Do you want secure chat? (yes/no): ").lower().startswith('y')
        if secure:
            print("Initiating secure connection...")
            if self.chat_initiator.initiate_secure_chat(peer_data['ip']):
                self.encryption_enabled = True
                print("Secure chat established!")
            else:
                print("Failed to establish secure chat")
                self.current_chat = None
                return
        else:
            self.encryption_enabled = False
        
        print("Type /back to return to main menu")
        self._show_chat_log(peer)
                
    def _toggle_encryption(self):
        """Toggle encryption for current chat"""
        if not self.current_chat:
            print("Start a chat first")
            return
            
        peer_data = self.peers.get(self.current_chat)
        if not peer_data:
            print(f"Peer {self.current_chat} is no longer available")
            self.current_chat = None
            return
            
        if not self.encryption_enabled:
            print("Enabling encryption...")
            if self.chat_initiator.initiate_secure_chat(peer_data['ip']):
                self.encryption_enabled = True
                print("Encryption enabled")
            else:
                print("Failed to enable encryption")
        else:
            self.encryption_enabled = False
            print("Encryption disabled")
            
    def _send_message(self, message: str):
        """Send message to current chat peer"""
        if message == "/back":
            self.current_chat = None
            print("Returned to main menu")
            return
            
        peer_data = self.peers.get(self.current_chat)
        if not peer_data:
            print(f"Peer {self.current_chat} is no longer available")
            self.current_chat = None
            return
            
        try:
            self.chat_initiator.send_message(
                self.current_chat,
                message,
                peer_data['ip'],
                self.encryption_enabled
            )
        except Exception as e:
            print(f"Error sending message: {e}")
            
    def _on_peers_update(self, peers):
        """Called when the peers list is updated"""
        self.peers = peers
    
    def _on_message_received(self, sender: str, content: str, encrypted: bool):
        """Called when a new message is received"""
        if sender == self.current_chat:
            encryption_status = "[Encrypted] " if encrypted else ""
            # Kullanıcının giriş satırını bozmadan mesajı yazdır
            sys.stderr.write(f"\r\033[K\n{sender}: {encryption_status}{content}\n> ")
            sys.stderr.flush()
        else:
            # Kullanıcının giriş satırını bozmadan bildirimi yazdır
            sys.stderr.write(f"\r\033[K\033[1;32m\nNew message from {sender}! Type 'chat {sender}' to view.\033[0m\n> ")
            sys.stderr.flush()

if __name__ == "__main__":
    app = ChatApplication()
    app.start()
