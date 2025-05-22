import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization
import os
import time
import timeit
import psutil
import socket
import threading
import queue
import struct
import ascon

class EncryptionTool:
    def __init__(self, root):
        self.root = root
        self.root.title("VM Encryption Tool with Latency Monitoring")
        self.root.geometry("900x700")
        
        # Encryption settings
        self.encryption_methods = ["AES128", "ASCON", "ChaCha20"]
        self.selected_method = tk.StringVar(value="AES128")
        self.shared_key = None
        
        # Diffie-Hellman setup
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        self.private_key = self.dh_parameters.generate_private_key()
        
        # Network settings
        self.host_ip = socket.gethostbyname(socket.gethostname())
        self.port = 5000
        self.remote_ip = tk.StringVar(value="192.168.1.2")
        self.connection_status = False
        self.socket = None
        
        # Statistics
        self.sent_bytes = 0
        self.received_bytes = 0
        self.encryption_times = []
        self.decryption_times = []
        self.memory_usage = []
        self.latency_history = []
        
        # Packet handling
        self.packet_queue = queue.Queue()
        self.packet_size = 1024
        
        self.create_widgets()
        
        # Start threads
        self.monitor_thread = threading.Thread(target=self.monitor_resources, daemon=True)
        self.monitor_thread.start()
        
        self.process_thread = threading.Thread(target=self.process_packets, daemon=True)
        self.process_thread.start()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Connection Frame
        conn_frame = ttk.LabelFrame(main_frame, text="Connection Settings", padding="10")
        conn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(conn_frame, text="Local IP:").grid(row=0, column=0, sticky=tk.W)
        ttk.Label(conn_frame, text=self.host_ip).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(conn_frame, text="Remote IP:").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(conn_frame, textvariable=self.remote_ip).grid(row=1, column=1, sticky=tk.EW)
        
        ttk.Label(conn_frame, text="Port:").grid(row=2, column=0, sticky=tk.W)
        ttk.Label(conn_frame, text=str(self.port)).grid(row=2, column=1, sticky=tk.W)
        
        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self.toggle_connection)
        self.connect_btn.grid(row=3, column=0, columnspan=2, pady=5)
        
        # Key Exchange Frame
        key_frame = ttk.LabelFrame(main_frame, text="Key Exchange", padding="10")
        key_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(key_frame, text="Perform Key Exchange", 
                  command=self.perform_key_exchange).pack(pady=5)
        
        # Encryption Frame
        enc_frame = ttk.LabelFrame(main_frame, text="Encryption Settings", padding="10")
        enc_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(enc_frame, text="Method:").grid(row=0, column=0, sticky=tk.W)
        ttk.Combobox(enc_frame, textvariable=self.selected_method, 
                    values=self.encryption_methods, state="readonly").grid(row=0, column=1, sticky=tk.EW)
        
        # Data Frame
        data_frame = ttk.LabelFrame(main_frame, text="Data Transfer", padding="10")
        data_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.message_entry = ttk.Entry(data_frame)
        self.message_entry.pack(fill=tk.X, pady=5)
        
        button_frame = ttk.Frame(data_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Send Text", command=self.send_text).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Send File", command=self.send_file).pack(side=tk.LEFT, padx=5)
        
        self.text_display = tk.Text(data_frame, height=10)
        self.text_display.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Stats Frame
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.bandwidth_label = ttk.Label(stats_frame, text="Bandwidth: Sent 0 bytes | Received 0 bytes")
        self.bandwidth_label.pack(anchor=tk.W)
        
        self.memory_label = ttk.Label(stats_frame, text="Memory Usage: 0 MB")
        self.memory_label.pack(anchor=tk.W)
        
        self.time_label = ttk.Label(stats_frame, text="Encryption Time: 0 ms avg | Decryption Time: 0 ms avg")
        self.time_label.pack(anchor=tk.W)
        
        self.latency_label = ttk.Label(stats_frame, text="Network Latency: 0 ms avg")
        self.latency_label.pack(anchor=tk.W)
        
        # Configure grid weights
        conn_frame.columnconfigure(1, weight=1)
        enc_frame.columnconfigure(1, weight=1)

    def perform_key_exchange(self):
        if not self.connection_status:
            messagebox.showerror("Error", "Not connected to remote VM")
            return
            
        try:
            # Send our public key
            public_key = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.socket.sendall(struct.pack('!I', len(public_key)))
            self.socket.sendall(public_key)
            
            # Receive remote public key
            length_data = self.recvall(4)
            if not length_data:
                raise ConnectionError("Failed to receive key length")
            key_length = struct.unpack('!I', length_data)[0]
            remote_public_key_bytes = self.recvall(key_length)
            
            remote_public_key = serialization.load_pem_public_key(
                remote_public_key_bytes,
                backend=default_backend()
            )
            
            # Generate shared key
            shared_secret = self.private_key.exchange(remote_public_key)
            
            # Derive encryption key
            self.shared_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'vm_encryption_tool',
                backend=default_backend()
            ).derive(shared_secret)
            
            messagebox.showinfo("Success", "Key exchange completed successfully!")
            self.display_message("New encryption key established via Diffie-Hellman")
            
        except Exception as e:
            messagebox.showerror("Key Exchange Failed", str(e))

    def send_data(self, data, is_file=False):
        try:
            start_full = timeit.default_timer()
            
            packets = [data[i:i+self.packet_size] for i in range(0, len(data), self.packet_size)]
            
            for packet in packets:
                # Encrypt the packet
                start_time = timeit.default_timer()
                encrypted_packet = self.encrypt(packet)
                encryption_time = (timeit.default_timer() - start_time) * 1000
                self.encryption_times.append(encryption_time)
                
                # Add timestamp and length header
                timestamp = struct.pack('!d', timeit.default_timer())
                packet_to_send = timestamp + struct.pack('!I', len(encrypted_packet)) + encrypted_packet
                
                # Send the packet
                self.socket.sendall(packet_to_send)
                self.sent_bytes += len(packet_to_send)
                
                # Update stats
                self.update_stats()
            
            total_time = (timeit.default_timer() - start_full) * 1000
            self.display_message(f"Transfer completed in {total_time:.2f} ms")
            
        except Exception as e:
            self.display_message(f"Error sending data: {str(e)}")

    def receive_data(self):
        try:
            while self.connection_status:
                # Read timestamp (first 8 bytes)
                timestamp_data = self.recvall(8)
                if not timestamp_data:
                    break
                send_time = struct.unpack('!d', timestamp_data)[0]
                
                # Read packet length (next 4 bytes)
                length_data = self.recvall(4)
                if not length_data:
                    break
                packet_length = struct.unpack('!I', length_data)[0]
                
                # Read the actual packet
                encrypted_packet = self.recvall(packet_length)
                if not encrypted_packet:
                    break
                
                # Calculate latency
                recv_time = timeit.default_timer()
                latency_ms = (recv_time - send_time) * 1000
                self.latency_history.append(latency_ms)
                self.received_bytes += packet_length + 12  # +12 for headers
                
                # Add to processing queue
                self.packet_queue.put(encrypted_packet)
                
                # Update stats
                self.update_stats()
                
        except ConnectionResetError:
            self.display_message("Connection reset by peer.")
            self.disconnect()
        except Exception as e:
            self.display_message(f"Error receiving data: {str(e)}")
            self.disconnect()

    def process_packets(self):
        while True:
            encrypted_packet = self.packet_queue.get()
            
            try:
                # Decrypt the packet
                start_time = timeit.default_timer()
                decrypted_packet = self.decrypt(encrypted_packet)
                decryption_time = (timeit.default_timer() - start_time) * 1000
                self.decryption_times.append(decryption_time)
                
                # Display latency for this packet
                if self.latency_history:
                    self.display_message(f"Packet received (latency: {self.latency_history[-1]:.2f} ms)")
                
                # Display content
                try:
                    text = decrypted_packet.decode('utf-8')
                    self.display_message(f"Received: {text}")
                except UnicodeDecodeError:
                    self.display_message(f"Received binary data ({len(decrypted_packet)} bytes)")
                
                # Update stats
                self.update_stats()
                
            except Exception as e:
                self.display_message(f"Error processing packet: {str(e)}")
            
            self.packet_queue.task_done()

    def encrypt(self, data):
        if not self.shared_key:
            raise ValueError("No shared key established. Perform key exchange first.")
            
        method = self.selected_method.get()
        
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
            ciphertext = ascon.encrypt(self.shared_key[:16], nonce, associated_data, data)
            return nonce + ciphertext
            
        elif method == "ChaCha20":
            nonce = os.urandom(16)
            cipher = Cipher(algorithms.ChaCha20(self.shared_key, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data)
            return nonce + ciphertext

    def decrypt(self, encrypted_data):
        if not self.shared_key:
            raise ValueError("No shared key established. Perform key exchange first.")
            
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
            return ascon.decrypt(self.shared_key[:16], nonce, associated_data, ciphertext)
            
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
        self.bandwidth_label.config(
            text=f"Bandwidth: Sent {self.sent_bytes} bytes | Received {self.received_bytes} bytes")
        
        # Memory (average of last 5 measurements)
        recent_memory = self.memory_usage[-5:] if len(self.memory_usage) >= 5 else self.memory_usage
        avg_memory = sum(recent_memory) / len(recent_memory) if recent_memory else 0
        self.memory_label.config(text=f"Memory Usage: {avg_memory:.2f} MB")
        
        # Encryption/decryption times (average of last 10)
        recent_enc = self.encryption_times[-10:] if len(self.encryption_times) >= 10 else self.encryption_times
        avg_enc = sum(recent_enc) / len(recent_enc) if recent_enc else 0
        
        recent_dec = self.decryption_times[-10:] if len(self.decryption_times) >= 10 else self.decryption_times
        avg_dec = sum(recent_dec) / len(recent_dec) if recent_dec else 0
        
        self.time_label.config(
            text=f"Encryption Time: {avg_enc:.2f} ms avg | Decryption Time: {avg_dec:.2f} ms avg")
        
        # Latency (average of last 10)
        recent_lat = self.latency_history[-10:] if len(self.latency_history) >= 10 else self.latency_history
        avg_lat = sum(recent_lat) / len(recent_lat) if recent_lat else 0
        self.latency_label.config(text=f"Network Latency: {avg_lat:.2f} ms avg")

    def recvall(self, length):
        data = b''
        while len(data) < length:
            packet = self.socket.recv(length - len(data))
            if not packet:
                return None
            data += packet
        return data

    def toggle_connection(self):
        if self.connection_status:
            self.disconnect()
        else:
            self.connect()

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.remote_ip.get(), self.port))
            self.connection_status = True
            self.connect_btn.config(text="Disconnect")
            
            self.receive_thread = threading.Thread(target=self.receive_data, daemon=True)
            self.receive_thread.start()
            
            self.display_message(f"Connected to {self.remote_ip.get()}:{self.port}")
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")

    def disconnect(self):
        if self.socket:
            self.socket.close()
            self.socket = None
        self.connection_status = False
        self.connect_btn.config(text="Connect")
        self.display_message("Disconnected")

    def send_text(self):
        message = self.message_entry.get()
        if message and self.connection_status:
            self.message_entry.delete(0, tk.END)
            self.send_data(message.encode('utf-8'))

    def send_file(self):
        if not self.connection_status:
            messagebox.showerror("Error", "Not connected to remote VM.")
            return
            
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                self.send_data(data, is_file=True)
                self.display_message(f"File {file_path} sent successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to send file: {str(e)}")

    def display_message(self, message):
        self.text_display.insert(tk.END, message + "\n")
        self.text_display.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionTool(root)
    root.mainloop()