import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
import queue
import struct
import os
import time
import timeit
import psutil
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from ascon import ascon_encrypt, ascon_decrypt

class EncryptionServer:
    def __init__(self, root):
        self.root = root
        self.root.title("VM Encryption Server")
        self.root.geometry("900x700")
        
        # Encryption settings
        self.encryption_methods = ["AES128", "ASCON", "ChaCha20"]
        self.selected_method = tk.StringVar(value="AES128")
        self.shared_key = None
        
        # Network setup
        self.port = 5000
        self.socket = None
        self.connection_status = False
        
        # Statistics
        self.received_bytes = 0
        self.decryption_times = []
        self.memory_usage = []
        self.latency_history = []
        
        # Packet handling
        self.packet_queue = queue.Queue()
        self.packet_size = 1024
        
        # DH Key Exchange
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        self.private_key = self.dh_parameters.generate_private_key()
        
        self.create_widgets()
        self.start_server()
        
        # Start monitoring threads
        self.monitor_thread = threading.Thread(target=self.monitor_resources, daemon=True)
        self.monitor_thread.start()
        
        self.process_thread = threading.Thread(target=self.process_packets, daemon=True)
        self.process_thread.start()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Server Info Frame
        info_frame = ttk.LabelFrame(main_frame, text="Server Information", padding="10")
        info_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(info_frame, text="Listening IP:").grid(row=0, column=0, sticky=tk.W)
        ttk.Label(info_frame, text=socket.gethostbyname(socket.gethostname())).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(info_frame, text="Port:").grid(row=1, column=0, sticky=tk.W)
        ttk.Label(info_frame, text=str(self.port)).grid(row=1, column=1, sticky=tk.W)
        
        # Encryption Settings
        enc_frame = ttk.LabelFrame(main_frame, text="Encryption Settings", padding="10")
        enc_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(enc_frame, text="Method:").grid(row=0, column=0, sticky=tk.W)
        ttk.Combobox(enc_frame, textvariable=self.selected_method, 
                    values=self.encryption_methods, state="readonly").grid(row=0, column=1, sticky=tk.EW)
        
        # Activity Log
        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = tk.Text(log_frame, height=15)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Statistics Frame
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.bandwidth_label = ttk.Label(stats_frame, text="Received: 0 bytes")
        self.bandwidth_label.pack(anchor=tk.W)
        
        self.memory_label = ttk.Label(stats_frame, text="Memory Usage: 0 MB")
        self.memory_label.pack(anchor=tk.W)
        
        self.time_label = ttk.Label(stats_frame, text="Decryption Time: 0 ms avg")
        self.time_label.pack(anchor=tk.W)
        
        self.latency_label = ttk.Label(stats_frame, text="Network Latency: 0 ms avg")
        self.latency_label.pack(anchor=tk.W)
        
        # Configure grid weights
        info_frame.columnconfigure(1, weight=1)
        enc_frame.columnconfigure(1, weight=1)

    def start_server(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Remove problematic socket option and use SO_REUSEADDR instead
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(1)
            self.connection_status = True
            self.log_message(f"Server listening on port {self.port}")
            
            threading.Thread(target=self.accept_connections, daemon=True).start()
        except Exception as e:
            # Simplified error handling
            self.log_message(f"Server failed to start: {str(e)}")
            if hasattr(e, 'winerror'):
                self.log_message(f"Windows Error Code: {e.winerror}")

    def accept_connections(self):
        try:
            while self.connection_status:
                conn, addr = self.socket.accept()
                self.log_message(f"Connection from: {addr}")
                self.handle_client(conn)
        except Exception as e:
            self.log_message(f"Connection error: {str(e)}")

    def handle_client(self, conn):
        try:
            # Key exchange
            public_key = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            conn.sendall(struct.pack('!I', len(public_key)))
            conn.sendall(public_key)
            
            # Receive client's public key
            length_data = self.recvall(conn, 4)
            key_length = struct.unpack('!I', length_data)[0]
            remote_public_key_bytes = self.recvall(conn, key_length)
            
            remote_public_key = serialization.load_pem_public_key(
                remote_public_key_bytes,
                backend=default_backend()
            )
            
            # Generate shared key
            shared_secret = self.private_key.exchange(remote_public_key)
            self.shared_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'vm_encryption_tool',
                backend=default_backend()
            ).derive(shared_secret)
            
            self.log_message("Key exchange completed!")
            
            # Start receiving data
            self.receive_data(conn)
            
        except Exception as e:
            self.log_message(f"Key exchange failed: {str(e)}")

    def receive_data(self, conn):
        try:
            while self.connection_status:
                # Read timestamp
                timestamp_data = self.recvall(conn, 8)
                if not timestamp_data:
                    break
                send_time = struct.unpack('!d', timestamp_data)[0]
                
                # Read packet length
                length_data = self.recvall(conn, 4)
                if not length_data:
                    break
                packet_length = struct.unpack('!I', length_data)[0]
                
                # Read encrypted packet
                encrypted_packet = self.recvall(conn, packet_length)
                if not encrypted_packet:
                    break
                
                # Calculate latency
                recv_time = timeit.default_timer()
                latency_ms = (recv_time - send_time) * 1000
                self.latency_history.append(latency_ms)
                self.received_bytes += packet_length + 12
                
                # Add to processing queue
                self.packet_queue.put(encrypted_packet)
                
                # Update stats
                self.update_stats()
                
        except Exception as e:
            self.log_message(f"Receive error: {str(e)}")

    def process_packets(self):
        while True:
            encrypted_packet = self.packet_queue.get()
            
            try:
                # Decrypt the packet
                start_time = timeit.default_timer()
                decrypted_packet = self.decrypt(encrypted_packet)
                decryption_time = (timeit.default_timer() - start_time) * 1000
                self.decryption_times.append(decryption_time)
                
                # Display content
                try:
                    text = decrypted_packet.decode('utf-8')
                    self.log_message(f"Received: {text}")
                except UnicodeDecodeError:
                    self.log_message(f"Received binary data ({len(decrypted_packet)} bytes)")
                
                # Update stats
                self.update_stats()
                
            except Exception as e:
                self.log_message(f"Decryption error: {str(e)}")
            
            self.packet_queue.task_done()

    def decrypt(self, encrypted_data):
        if not self.shared_key:
            raise ValueError("No shared key established")
            
        method = self.selected_method.get()
        
        if method == "AES128":
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            cipher = Cipher(algorithms.AES(self.shared_key[:16]), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()
            
        elif method == "ASCON":
            nonce = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            associated_data = b""
            return ascon_decrypt(self.shared_key[:16], nonce, associated_data, ciphertext)
            
        elif method == "ChaCha20":
            nonce = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            cipher = Cipher(algorithms.ChaCha20(self.shared_key, nonce), mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext)

    def monitor_resources(self):
        while True:
            memory = psutil.virtual_memory().used / (1024 * 1024)
            self.memory_usage.append(memory)
            time.sleep(1)

    def update_stats(self):
        # Bandwidth
        self.bandwidth_label.config(text=f"Received: {self.received_bytes} bytes")
        
        # Memory (average of last 5)
        recent_memory = self.memory_usage[-5:] if self.memory_usage else [0]
        avg_memory = sum(recent_memory) / len(recent_memory)
        self.memory_label.config(text=f"Memory Usage: {avg_memory:.2f} MB")
        
        # Decryption times (average of last 10)
        recent_dec = self.decryption_times[-10:] if self.decryption_times else [0]
        avg_dec = sum(recent_dec) / len(recent_dec)
        self.time_label.config(text=f"Decryption Time: {avg_dec:.2f} ms avg")
        
        # Latency (average of last 10)
        recent_lat = self.latency_history[-10:] if self.latency_history else [0]
        avg_lat = sum(recent_lat) / len(recent_lat)
        self.latency_label.config(text=f"Network Latency: {avg_lat:.2f} ms avg")

    def recvall(self, sock, length):
        data = b''
        while len(data) < length:
            try:
                packet = sock.recv(length - len(data))
                if not packet:
                    raise ConnectionError("Socket closed prematurely")
                data += packet
            except socket.timeout:
                print("[ERROR] Timeout waiting for data")
                break
        return data if len(data) == length else None

    def log_message(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    server = EncryptionServer(root)
    root.mainloop()
