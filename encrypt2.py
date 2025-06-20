import tkinter as tk
from tkinter import ttk, messagebox
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

class EncryptionServer:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption Server")
        self.root.geometry("900x700")
        
        # Create a directory for received files
        self.downloads_dir = "Downloads"
        os.makedirs(self.downloads_dir, exist_ok=True)

        # Encryption settings
        self.encryption_methods = ["No Encryption", "AES128", "ASCON", "ChaCha20"]
        self.selected_method = tk.StringVar(value=" ")
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

    def reset_statistics(self):
        self.received_bytes = 0
        self.decryption_times.clear()
        self.memory_usage.clear()
        self.latency_history.clear()
        #self.log_message("--- Statistics Reset Manually ---")
        self.update_stats()

    def start_server(self):
        try:
            # Initialize socket first
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                self.socket.bind(('0.0.0.0', self.port))
                self.socket.listen(5)
                self.connection_status = True
                self.log_message(f"Server successfully started on port {self.port}")
                
                # Start accept thread only if binding succeeded
                threading.Thread(target=self.accept_connections, daemon=True).start()
            except Exception as bind_error:
                self.log_message(f"Binding failed: {str(bind_error)}")
                self.socket.close()
                self.socket = None  # Explicitly set to None
                
        except Exception as e:
            self.log_message(f"Server startup failed: {str(e)}")
            if hasattr(self, 'socket') and self.socket:
                self.socket.close()
            self.socket = None
            self.connection_status = False

    def accept_connections(self):
        while self.connection_status:
            try:
                conn, addr = self.socket.accept()  

                try:
                    if not all(c.isdigit() or c == '.' for c in addr[0]):
                        self.log_message(f"Invalid IP format: {addr[0]}")
                        conn.close()
                        continue
                        
                    self.log_message(f"Connection from: {addr[0]}:{addr[1]}")
                    threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()
                    
                except Exception as e:
                    self.log_message(f"Connection validation failed: {str(e)}")
                    conn.close()
                    
            except Exception as e:
                if self.connection_status:  # Only log if server is still running
                    self.log_message(f"Accept error: {str(e)}")

    def handle_client(self, conn):
        try:
            # Send public key
            param_bytes = self.dh_parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            )
            conn.sendall(struct.pack('!I', len(param_bytes)))
            conn.sendall(param_bytes)
            self.log_message("Sent DH parameters to the client.")

            public_key = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            conn.sendall(struct.pack('!I', len(public_key)))
            conn.sendall(public_key)
            
            # Receive client's public key
            length_data = self.recvall(conn, 4)
            if not length_data:
                raise ValueError("No key length received")
                
            key_length = struct.unpack('!I', length_data)[0]
            remote_public_key_bytes = self.recvall(conn, key_length)
            
            if not remote_public_key_bytes:
                raise ValueError("No public key received")
                
            # Load client's public key
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
            self.receive_data(conn)
            
        except Exception as e:
            conn.close()

        while True:
                # Receive header
                header_len_data = self.recvall(conn, 4)
                if not header_len_data: break # Client disconnected gracefully
                header_len = struct.unpack('!I', header_len_data)[0]
                header_bytes = self.recvall(conn, header_len)
                if not header_bytes: break
                header = json.loads(header_bytes.decode('utf-8'))
                
                self.log_message(f"Receiving new transfer: {header}")
                self.reset_statistics()
                
                # Prepare to receive data based on header
                total_size = header['size']
                bytes_received = 0
                data_buffer = []

                # Determine save path for files
                save_path = None
                if header['type'] == 'file':
                    base_filename = header['filename']
                    save_path = os.path.join(self.downloads_dir, base_filename)
                    # Avoid overwriting files
                    counter = 1
                    while os.path.exists(save_path):
                        name, ext = os.path.splitext(base_filename)
                        save_path = os.path.join(self.downloads_dir, f"{name}({counter}){ext}")
                        counter += 1
                    file_writer = open(save_path, 'wb')

                # Receive all packets for this transfer
                while bytes_received < total_size:
                    # Read packet
                    timestamp_data = self.recvall(conn, 8)
                    if not timestamp_data: raise ValueError("Connection lost mid-transfer.")
                    send_time = struct.unpack('!d', timestamp_data)[0]

                    length_data = self.recvall(conn, 4)
                    if not length_data: raise ValueError("Connection lost mid-transfer.")
                    packet_length = struct.unpack('!I', length_data)[0]

                    encrypted_packet = self.recvall(conn, packet_length)
                    if not encrypted_packet: raise ValueError("Connection lost mid-transfer.")   

                 #Decrypt and process
                start_time = timeit.default_timer()
                decrypted_chunk = self.decrypt(encrypted_packet)
                decryption_time = (timeit.default_timer() - start_time) * 1000
    
                bytes_received += len(decrypted_chunk)
                    
                if header['type'] == 'file':
                    file_writer.write(decrypted_chunk)
                else: # 'text'
                    data_buffer.append(decrypted_chunk)

                # Update stats
                self.decryption_times.append(decryption_time)
                self.latency_history.append((start_time - send_time) * 1000)
                self.received_bytes += packet_length + 12
                self.update_stats() 

                # Finalize transfer
                if header['type'] == 'file':
                    file_writer.close()
                    self.log_message(f"File saved successfully to: {save_path}")
                else:
                    full_message = b''.join(data_buffer).decode('utf-8')
                    self.log_message(f"Received Text: {full_message}")
   
    def decrypt(self, encrypted_data):
        method = self.selected_method.get()

        if method == "No Encryption":
            return encrypted_data
        
        if not self.shared_key:
            raise ValueError("No shared key established")
            
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
        
        # Memory 
        if self.memory_usage:
            avg_memory = sum(self.memory_usage) / len(self.memory_usage)
            self.memory_label.config(text=f"Memory Usage: {avg_memory:.2f} MB")
        else:
            self.memory_label.config(text="Memory Usage: 0.00 MB")
        
        # Decryption times 
        if self.decryption_times:
            avg_dec = sum(self.decryption_times) / len(self.decryption_times)
            self.time_label.config(text=f"Decryption Time: {avg_dec:.2f} ms avg")
        else:
            self.time_label.config(text="Decryption Time: 0.00 ms avg")
        
        # Latency 
        if self.latency_history:
            avg_lat = sum(self.latency_history) / len(self.latency_history)
            self.latency_label.config(text=f"Network Latency: {avg_lat:.2f} ms avg")
        else:
            self.latency_label.config(text="Network Latency: 0.00 ms avg")

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
