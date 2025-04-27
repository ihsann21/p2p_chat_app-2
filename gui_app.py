import tkinter as tk
from tkinter import ttk, scrolledtext, simpledialog, messagebox
import threading
import time
from datetime import datetime

from peer_discovery import PeerDiscovery
from service_announcer import ServiceAnnouncer
from chat_responder import ChatResponder
from chat_initiator import ChatInitiator

class ChatAppGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("P2P Chat Application")
        self.root.geometry("800x600")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.username = None
        self.current_chat = None
        self.encryption_enabled = False
        self.peers = {}
        
        self.create_widgets()
        self.init_application()
    
    def create_widgets(self):
        # Create main notebook with tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create main tab frames
        self.main_tab = ttk.Frame(self.notebook)
        self.chat_tab = ttk.Frame(self.notebook)
        self.history_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.main_tab, text="Users")
        self.notebook.add(self.chat_tab, text="Chat")
        self.notebook.add(self.history_tab, text="History")
        
        # Users tab
        self.setup_users_tab()
        
        # Chat tab
        self.setup_chat_tab()
        
        # History tab
        self.setup_history_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Welcome to P2P Chat")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_users_tab(self):
        # Frame for users list
        users_frame = ttk.LabelFrame(self.main_tab, text="Available Users")
        users_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Listbox to display users
        self.users_listbox = tk.Listbox(users_frame, height=15)
        self.users_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Scrollbar for users list
        users_scrollbar = ttk.Scrollbar(users_frame, orient=tk.VERTICAL, command=self.users_listbox.yview)
        users_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.users_listbox.config(yscrollcommand=users_scrollbar.set)
        
        # Frame for buttons
        button_frame = ttk.Frame(self.main_tab)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Refresh button
        refresh_btn = ttk.Button(button_frame, text="Refresh", command=self.refresh_users)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        # Chat button
        chat_btn = ttk.Button(button_frame, text="Start Chat", command=self.start_chat_with_selected)
        chat_btn.pack(side=tk.LEFT, padx=5)
    
    def setup_chat_tab(self):
        # Main chat area
        chat_main_frame = ttk.Frame(self.chat_tab)
        chat_main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Frame for showing current chat peer
        chat_header_frame = ttk.Frame(chat_main_frame)
        chat_header_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.chat_peer_var = tk.StringVar()
        self.chat_peer_var.set("No active chat")
        
        chat_peer_label = ttk.Label(chat_header_frame, text="Chatting with: ")
        chat_peer_label.pack(side=tk.LEFT)
        
        chat_peer_name = ttk.Label(chat_header_frame, textvariable=self.chat_peer_var, font=("TkDefaultFont", 10, "bold"))
        chat_peer_name.pack(side=tk.LEFT)
        
        # Encryption toggle
        self.encryption_var = tk.BooleanVar()
        encryption_check = ttk.Checkbutton(
            chat_header_frame, 
            text="Encrypted", 
            variable=self.encryption_var,
            command=self.toggle_encryption
        )
        encryption_check.pack(side=tk.RIGHT)
        
        # Chat history display
        chat_display_frame = ttk.LabelFrame(chat_main_frame, text="Messages")
        chat_display_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.chat_display = scrolledtext.ScrolledText(chat_display_frame, state='disabled', wrap=tk.WORD)
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Message input area
        message_frame = ttk.Frame(chat_main_frame)
        message_frame.pack(fill=tk.X, pady=5)
        
        self.message_input = ttk.Entry(message_frame)
        self.message_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_input.bind("<Return>", lambda event: self.send_message())
        
        send_btn = ttk.Button(message_frame, text="Send", command=self.send_message)
        send_btn.pack(side=tk.RIGHT)
        
        # Button to end chat
        end_chat_btn = ttk.Button(chat_main_frame, text="End Chat", command=self.end_chat)
        end_chat_btn.pack(pady=5)
    
    def setup_history_tab(self):
        # Frame for history options
        options_frame = ttk.Frame(self.history_tab)
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Dropdown for selecting peer
        ttk.Label(options_frame, text="Select peer:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.peer_var = tk.StringVar()
        self.peer_dropdown = ttk.Combobox(options_frame, textvariable=self.peer_var)
        self.peer_dropdown.pack(side=tk.LEFT, padx=5)
        
        # Button to show history
        show_btn = ttk.Button(options_frame, text="Show History", command=self.show_chat_history)
        show_btn.pack(side=tk.LEFT, padx=5)
        
        # History display
        history_frame = ttk.LabelFrame(self.history_tab, text="Chat History")
        history_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.history_display = scrolledtext.ScrolledText(history_frame, state='disabled', wrap=tk.WORD)
        self.history_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def init_application(self):
        # Ask for username
        self.username = simpledialog.askstring("Username", "Enter your username:", parent=self.root)
        if not self.username:
            messagebox.showerror("Error", "Username is required")
            self.root.destroy()
            return
        
        self.status_var.set(f"Initializing application for {self.username}...")
        self.root.update()
        
        try:
            # Initialize all processes
            self.peer_discovery = PeerDiscovery()
            self.service_announcer = ServiceAnnouncer()
            self.chat_responder = ChatResponder(self.username)
            self.chat_initiator = ChatInitiator(self.username)
            
            # Start services
            self.status_var.set("Starting peer discovery service...")
            self.root.update()
            self.peer_discovery.start(self.username)
            
            self.status_var.set("Starting service announcer...")
            self.root.update()
            self.service_announcer.start(self.username)
            
            self.status_var.set("Starting chat responder...")
            self.root.update()
            self.chat_responder.start()
            
            # Setup callbacks
            self.peer_discovery.add_peer_callback(self.on_peers_update)
            self.chat_responder.set_message_callback(self.on_message_received)
            
            self.status_var.set(f"Welcome {self.username}! Ready to chat.")
            
            # Start periodic updates
            self.update_ui()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error initializing application: {e}")
            self.root.destroy()
    
    def update_ui(self):
        """Periodically update UI elements"""
        # Update users list
        self.refresh_users()
        
        # Update peer dropdown in history tab
        all_peers = set()
        for peer in self.chat_responder.chat_log.keys():
            all_peers.add(peer)
        for peer in self.chat_initiator.chat_log.keys():
            all_peers.add(peer)
        
        self.peer_dropdown['values'] = list(all_peers)
        
        # Schedule next update
        self.root.after(5000, self.update_ui)
    
    def refresh_users(self):
        """Update the users list"""
        peers = self.peer_discovery.get_peers()
        self.peers = peers
        
        self.users_listbox.delete(0, tk.END)
        if not peers:
            self.users_listbox.insert(tk.END, "No peers found")
        else:
            for username, data in peers.items():
                self.users_listbox.insert(tk.END, f"{username} {data['status']}")
    
    def start_chat_with_selected(self):
        """Start chat with the selected user"""
        selection = self.users_listbox.curselection()
        if not selection:
            messagebox.showinfo("Info", "Please select a user")
            return
        
        selected_item = self.users_listbox.get(selection[0])
        if selected_item == "No peers found":
            return
        
        # Extract username from the list item
        peer = selected_item.split()[0]
        
        self.start_chat(peer)
    
    def start_chat(self, peer):
        """Start chat with peer"""
        if peer not in self.peers:
            messagebox.showerror("Error", f"Peer {peer} not found")
            return
        
        self.current_chat = peer
        peer_data = self.peers[peer]
        
        self.status_var.set(f"Starting chat with {peer}")
        self.chat_peer_var.set(peer)
        
        # Ask for secure chat
        secure = messagebox.askyesno("Secure Chat", "Do you want secure chat?")
        
        if secure:
            self.status_var.set("Initiating secure connection...")
            self.root.update()
            
            if self.chat_initiator.initiate_secure_chat(peer_data['ip']):
                self.encryption_enabled = True
                self.encryption_var.set(True)
                self.status_var.set("Secure chat established!")
            else:
                messagebox.showerror("Error", "Failed to establish secure chat")
                self.current_chat = None
                self.chat_peer_var.set("No active chat")
                return
        else:
            self.encryption_enabled = False
            self.encryption_var.set(False)
        
        # Show chat history
        self.display_chat_log(peer)
        
        # Switch to chat tab
        self.notebook.select(self.chat_tab)
    
    def display_chat_log(self, peer):
        """Display chat history with a specific peer"""
        # Get chat logs from both responder and initiator
        responder_log = self.chat_responder.get_chat_log(peer)
        initiator_log = self.chat_initiator.get_chat_log(peer)
        
        # Combine and sort logs by timestamp
        combined_log = responder_log + initiator_log
        combined_log.sort(key=lambda x: x['timestamp'])
        
        # Clear and update chat display
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        
        if not combined_log:
            self.chat_display.insert(tk.END, f"No chat history with {peer}\n")
        else:
            for msg in combined_log:
                prefix = "You:" if msg['sent'] else f"{peer}:"
                timestamp = datetime.fromisoformat(msg['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
                encrypted = "[Encrypted] " if msg['encrypted'] else ""
                
                self.chat_display.insert(tk.END, f"[{timestamp}] {prefix} {encrypted}{msg['content']}\n")
        
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)
    
    def send_message(self):
        """Send message to current chat peer"""
        if not self.current_chat:
            messagebox.showinfo("Info", "Start a chat first")
            return
        
        message = self.message_input.get().strip()
        if not message:
            return
        
        peer_data = self.peers.get(self.current_chat)
        if not peer_data:
            messagebox.showerror("Error", f"Peer {self.current_chat} is no longer available")
            self.end_chat()
            return
        
        try:
            self.chat_initiator.send_message(
                self.current_chat,
                message,
                peer_data['ip'],
                self.encryption_var.get()
            )
            
            # Clear input field
            self.message_input.delete(0, tk.END)
            
            # Update chat display
            self.display_chat_log(self.current_chat)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error sending message: {e}")
    
    def end_chat(self):
        """End current chat session"""
        self.current_chat = None
        self.chat_peer_var.set("No active chat")
        self.encryption_enabled = False
        self.encryption_var.set(False)
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        self.chat_display.config(state='disabled')
        
        # Switch to users tab
        self.notebook.select(self.main_tab)
    
    def toggle_encryption(self):
        """Toggle encryption for current chat"""
        if not self.current_chat:
            messagebox.showinfo("Info", "Start a chat first")
            self.encryption_var.set(False)
            return
        
        peer_data = self.peers.get(self.current_chat)
        if not peer_data:
            messagebox.showerror("Error", f"Peer {self.current_chat} is no longer available")
            self.encryption_var.set(False)
            self.end_chat()
            return
        
        if self.encryption_var.get() and not self.encryption_enabled:
            self.status_var.set("Enabling encryption...")
            self.root.update()
            
            if self.chat_initiator.initiate_secure_chat(peer_data['ip']):
                self.encryption_enabled = True
                self.status_var.set("Encryption enabled")
            else:
                messagebox.showerror("Error", "Failed to enable encryption")
                self.encryption_var.set(False)
        elif not self.encryption_var.get() and self.encryption_enabled:
            self.encryption_enabled = False
            self.status_var.set("Encryption disabled")
    
    def show_chat_history(self):
        """Show chat history with selected peer"""
        peer = self.peer_var.get()
        if not peer:
            messagebox.showinfo("Info", "Select a peer from the dropdown")
            return
        
        # Get chat logs from both responder and initiator
        responder_log = self.chat_responder.get_chat_log(peer)
        initiator_log = self.chat_initiator.get_chat_log(peer)
        
        # Combine and sort logs by timestamp
        combined_log = responder_log + initiator_log
        combined_log.sort(key=lambda x: x['timestamp'])
        
        # Clear and update history display
        self.history_display.config(state='normal')
        self.history_display.delete(1.0, tk.END)
        
        if not combined_log:
            self.history_display.insert(tk.END, f"No chat history with {peer}\n")
        else:
            for msg in combined_log:
                prefix = "You:" if msg['sent'] else f"{peer}:"
                timestamp = datetime.fromisoformat(msg['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
                encrypted = "[Encrypted] " if msg['encrypted'] else ""
                
                self.history_display.insert(tk.END, f"[{timestamp}] {prefix} {encrypted}{msg['content']}\n")
        
        self.history_display.config(state='disabled')
    
    def on_peers_update(self, peers):
        """Called when the peers list is updated"""
        self.peers = peers
        # Update on main thread
        self.root.after(0, self.refresh_users)
    
    def on_message_received(self, sender, content, encrypted):
        """Called when a new message is received"""
        if sender == self.current_chat:
            # Update chat display on main thread
            self.root.after(0, lambda: self.display_chat_log(sender))
            
            # Show notification
            encryption_status = "[Encrypted] " if encrypted else ""
            self.status_var.set(f"New message from {sender}: {encryption_status}{content[:20]}...")
        else:
            # Show notification
            self.status_var.set(f"New message from {sender}! Go to Users tab to start chat.")
            messagebox.showinfo("New Message", f"New message from {sender}!")
    
    def on_closing(self):
        """Handle window close event"""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            try:
                self.peer_discovery.stop()
                self.service_announcer.stop()
                self.chat_responder.stop()
                self.root.destroy()
            except:
                pass

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatAppGUI(root)
    root.mainloop() 