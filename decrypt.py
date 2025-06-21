import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import threading
import json
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

class EncryptionClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption Client")
        self.root.geometry("900x700")
        
        # Encryption settings
        self.encryption_methods = ["No Encryption", "AES128", "ASCON", "ChaCha20"]
        self.selected_method = tk.StringVar(value="No Encryption")
        self.selected_method = tk.StringVar(value=" ")
        self.shared_key = None
        
        # Network setup
        self.server_ip = tk.StringVar(value=" ")
        self.port = 5000
        self.socket = None
        self.connection_status = False
        
        # Statistics
        self.sent_bytes = 0
        self.encryption_times = []
        self.memory_usage = []
        
        # Packet handling
        self.packet_queue = queue.Queue()
        self.packet_size = 1024
        
        # DH Key Exchange
        #self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        #self.private_key = self.dh_parameters.generate_private_key()
        self.private_key = None
        
        self.create_widgets()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_resources, daemon=True)
        self.monitor_thread.start()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Connection Frame
        conn_frame = ttk.LabelFrame(main_frame, text="Connection Settings", padding="10")
        conn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(conn_frame, text="Server IP:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(conn_frame, textvariable=self.server_ip).grid(row=0, column=1, sticky=tk.EW)
        
        ttk.Label(conn_frame, text="Port:").grid(row=1, column=0, sticky=tk.W)
        ttk.Label(conn_frame, text=str(self.port)).grid(row=1, column=1, sticky=tk.W)
        
        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self.toggle_connection)
        self.connect_btn.grid(row=2, columnspan=2, sticky=tk.EW, pady=5)
        
        # Encryption Settings
        enc_frame = ttk.LabelFrame(main_frame, text="Encryption Settings", padding="10")
        enc_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(enc_frame, text="Method:").grid(row=0, column=0, sticky=tk.W)
        ttk.Combobox(enc_frame, textvariable=self.selected_method, 
                    values=self.encryption_methods, state="readonly").grid(row=0, column=1, sticky=tk.EW)
        
        # Data Transfer
        data_frame = ttk.LabelFrame(main_frame, text="Data Transfer", padding="10")
        data_frame.pack(fill=tk.BOTH, expand=True)
        
        self.message_entry = ttk.Entry(data_frame)
        self.message_entry.pack(fill=tk.X, pady=5)
        
        button_frame = ttk.Frame(data_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Send Text", command=self.send_text).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Send File", command=self.send_file).pack(side=tk.LEFT, padx=5)
        
        self.log_text = tk.Text(data_frame, height=10)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Statistics Frame
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.bandwidth_label = ttk.Label(stats_frame, text="Sent: 0 bytes")
        self.bandwidth_label.pack(anchor=tk.W)
        
        self.memory_label = ttk.Label(stats_frame, text="Memory Usage: 0 MB")
        self.memory_label.pack(anchor=tk.W)
        
        self.time_label = ttk.Label(stats_frame, text="Encryption Time: 0 ms avg")
        self.time_label.pack(anchor=tk.W)
        
        # Configure grid weights
        conn_frame.columnconfigure(1, weight=1)
        enc_frame.columnconfigure(1, weight=1)

    def reset_statistics(self):
        self.sent_bytes = 0
        self.encryption_times.clear()
        self.memory_usage.clear()
        #self.log_message("--- Statistics Reset ---")
        self.update_stats()

    def toggle_connection(self):
        if self.connection_status:
            self.disconnect()
        else:
            self.connect()

    def connect(self):
        try:
            target_ip = self.server_ip.get().strip()
            
            # Basic IP validation
            if not all(c.isdigit() or c == '.' for c in target_ip):
                self.log_message("Invalid IP address format")
                return False
                
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            
            try:
                self.socket.connect((target_ip, self.port))
                self.log_message(f"Socket connected to {target_ip}. Initiating key exchange...")
                
                threading.Thread(target=self.perform_key_exchange, daemon=True).start()
                return True 
                    
            except socket.timeout:
                self.log_message(f"Connection to {target_ip} timed out.")
                if self.socket: self.socket.close()
                self.socket = None 
                return False 
            
            except Exception as e:
                self.log_message(f"Connection failed: {str(e)}")
                if self.socket: self.socket.close()
                self.socket = None 
                return False 
                
        except Exception as e: 
            self.log_message(f"Connection setup error: {str(e)}")
            if hasattr(self, 'socket') and self.socket: self.socket.close()
            self.socket = None
            return False
        
    def perform_key_exchange(self):
        if not self.socket:
            self.log_message("[ERROR] No active socket for key exchange")
            return
        
        try:
            #KEY EXCHANGE DEBUG
            self.log_message("[KEY] Starting key exchange...")
            
            param_len_data = self.recvall(4)
            if not param_len_data:
                raise ValueError("Did not receive parameter length from server.")
            
            param_len = struct.unpack('!I', param_len_data)[0]
            param_bytes = self.recvall(param_len)
            if not param_bytes:
                raise ValueError("Did not receive parameters from server.")
            
            received_parameters = serialization.load_pem_parameters(param_bytes, backend=default_backend())
            self.private_key = received_parameters.generate_private_key()
            self.log_message("[KEY] Received server parameters and generated new private key.")

            # Receive server's public key
            length_data = self.recvall(4)
            if not length_data:
                self.log_message("[ERROR] No key length received")
                return
                
            key_length = struct.unpack('!I', length_data)[0]
            self.log_message(f"[KEY] Expecting key of length: {key_length} bytes")
            
            remote_public_key_bytes = self.recvall(key_length)
            if not remote_public_key_bytes:
                self.log_message("[ERROR] Failed to receive public key")
                return
                
            remote_public_key = serialization.load_pem_public_key(
                remote_public_key_bytes,
                backend=default_backend()
            )

            #KEY VERIFICATION DEBUG
            self.log_message(f"[DEBUG] Received key (first 10 bytes): {remote_public_key_bytes[:10].hex()}...")
            
            remote_public_key = serialization.load_pem_public_key(
                remote_public_key_bytes,
                backend=default_backend()
            )
            
            # Send our public key
            public_key = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            self.socket.sendall(struct.pack('!I', len(public_key)))
            self.socket.sendall(public_key)
            
            # Generate shared key
            shared_secret = self.private_key.exchange(remote_public_key)
            self.shared_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'vm_encryption_tool',
                backend=default_backend()
            ).derive(shared_secret)
            
            #KEY VERIFICATION
            self.log_message(f"[DEBUG] Shared key established: {self.shared_key.hex()[:10]}...")
            self.log_message("Key exchange completed!")
            self.connection_status = True  
            self.root.after(0, lambda: self.connect_btn.config(text="Disconnect"))

        except Exception as e:
            self.log_message(f"Key exchange failed: {str(e)}")
            if hasattr(self, 'socket') and self.socket:
                self.socket.close()
                self.socket = None
            self.connection_status = False
            self.root.after(0, lambda: self.connect_btn.config(text="Connect"))
            
    def send_data(self, data):
        if not self.connection_status:
            self.log_message("Cannot send data: Not connected.")
            return
        try:
            packets = [data[i:i+self.packet_size] for i in range(0, len(data), self.packet_size)]

            for packet in packets:
                start_time = timeit.default_timer()
                encrypted_packet = self.encrypt(packet)
                encryption_time = (timeit.default_timer() - start_time) * 1000
                self.encryption_times.append(encryption_time)

                timestamp = struct.pack('!d', timeit.default_timer())
                packet_to_send = timestamp + struct.pack('!I', len(encrypted_packet)) + encrypted_packet

                self.socket.sendall(packet_to_send)
                self.sent_bytes += len(packet_to_send)

                self.update_stats()

            self.log_message("Data sent successfully")

        except Exception as e:
            self.log_message(f"Send error: {str(e)}")

    def encrypt(self, data):
        method = self.selected_method.get()
        if method == "No Encryption":
            return data
        
        if not self.shared_key:
            raise ValueError("No shared key established")
            
        
        if method == "AES128":
            iv = os.urandom(16)
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            cipher = Cipher(algorithms.AES(self.shared_key[:16]), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return iv + ciphertext
            
        elif method == "ASCON":
            nonce = os.urandom(16)
            associated_data = b""
            ciphertext = ascon_encrypt(self.shared_key[:16], nonce, associated_data, data)
            return nonce + ciphertext
            
        elif method == "ChaCha20":
            nonce = os.urandom(16)
            cipher = Cipher(algorithms.ChaCha20(self.shared_key, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data)
            return nonce + ciphertext

    def send_text(self):
        if not self.connection_status:
            messagebox.showerror("Error", "Not connected to server")
            return
            
        message = self.message_entry.get()
        if message:
            self.message_entry.delete(0, tk.END)
            threading.Thread(target=self.send_data, args=(message.encode('utf-8'),), daemon=True).start()

    def send_file(self):
        if not self.connection_status:
            messagebox.showerror("Error", "Not connected to server")
            return
            
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                threading.Thread(target=self.send_data, args=(data,), daemon=True).start()
                self.log_message(f"File {file_path} ready to send")
            except Exception as e:
                self.log_message(f"File error: {str(e)}")

    def monitor_resources(self):
        while True:
            memory = psutil.virtual_memory().used / (1024 * 1024)
            self.memory_usage.append(memory)
            time.sleep(1)

    def update_stats(self):
        # Bandwidth
        self.bandwidth_label.config(text=f"Sent: {self.sent_bytes} bytes")
        
        # Memory (average of last 5)
        if self.memory_usage:
            avg_memory = sum(self.memory_usage) / len(self.memory_usage)
            self.memory_label.config(text=f"Memory Usage: {avg_memory:.2f} MB")
        else:
            self.memory_label.config(text="Memory Usage: 0.00 MB")
        
        # Encryption times (average of last 10)
        if self.encryption_times:
            avg_enc = sum(self.encryption_times) / len(self.encryption_times)
            self.time_label.config(text=f"Encryption Time: {avg_enc:.2f} ms avg")
        else:
             self.time_label.config(text="Encryption Time: 0.00 ms avg")

    def recvall(self, length):
        data = b''
        while len(data) < length:
            packet = self.socket.recv(length - len(data))
            if not packet:
                return None
            data += packet
        return data

    def disconnect(self):
        if self.socket:
            self.socket.close()
        self.connection_status = False
        self.connect_btn.config(text="Connect")
        self.log_message("Disconnected")

    def log_message(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    client = EncryptionClient(root)
    root.mainloop()
