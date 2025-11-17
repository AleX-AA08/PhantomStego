#!/usr/bin/env python3
"""
Professional Steganography Tool
"""
import os
import sys
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import base64
import random
from PIL import Image
import piexif
import numpy as np
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def install_dependencies():
    """Install required dependencies"""
    try:
        from PIL import Image
        import piexif
        from cryptography.fernet import Fernet
        return True
    except ImportError:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", 
                                 "Pillow", "piexif", "cryptography", "numpy"])
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to install dependencies: {str(e)}")
            return False

class StegoTool:
    def __init__(self, root):
        self.root = root
        self.root.title("PhantomStego - Professional Steganography")
        self.root.geometry("700x700")
        self.root.resizable(True, True)
        
        # Variables
        self.payload_file = tk.StringVar()
        self.output_file = tk.StringVar()
        self.extract_input = tk.StringVar()
        self.extract_output = tk.StringVar()
        self.encrypt_input = tk.StringVar()
        self.encrypt_output = tk.StringVar()
        self.password = tk.StringVar(value="password123")
        self.method = tk.StringVar(value="exif")
        self.encryption = tk.StringVar(value="aes")
        self.use_encryption = tk.BooleanVar(value=True)
        self.encrypt_operation = tk.StringVar(value="encrypt")
        
        # Advanced settings
        self.polymorph = tk.BooleanVar(value=False)
        self.stealth_mode = tk.BooleanVar(value=False)
        
        self.create_widgets()
        
    def create_widgets(self):
        # Header
        header_frame = tk.Frame(self.root, bg="#2c3e50", height=60)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        tk.Label(header_frame, text="PhantomStego", font=("Arial", 16, "bold"), 
                fg="white", bg="#2c3e50").pack(pady=15)
        
        # Notebook
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Embed Tab
        embed_frame = ttk.Frame(notebook)
        notebook.add(embed_frame, text="🧩 Hide Payload")
        self.create_embed_tab(embed_frame)
        
        # Extract Tab
        extract_frame = ttk.Frame(notebook)
        notebook.add(extract_frame, text="🔍 Extract Payload")
        self.create_extract_tab(extract_frame)
        
        # Encrypt Tab
        encrypt_frame = ttk.Frame(notebook)
        notebook.add(encrypt_frame, text="🔒 File Encryption")
        self.create_encrypt_tab(encrypt_frame)
        
        # Settings Tab
        settings_frame = ttk.Frame(notebook)
        notebook.add(settings_frame, text="⚙️ Settings")
        self.create_settings_tab(settings_frame)
        
    def create_embed_tab(self, parent):
        # Payload file
        frame1 = tk.LabelFrame(parent, text="Payload File", font=("Arial", 10, "bold"))
        frame1.pack(fill="x", padx=15, pady=10)
        
        file_frame = tk.Frame(frame1)
        file_frame.pack(fill="x", padx=10, pady=5)
        tk.Entry(file_frame, textvariable=self.payload_file, font=("Arial", 9)).pack(side="left", fill="x", expand=True)
        tk.Button(file_frame, text="Browse", command=self.select_payload, 
                 width=10, bg="#3498db", fg="white").pack(side="right", padx=(5,0))
        
        # Output file
        frame2 = tk.LabelFrame(parent, text="Output File", font=("Arial", 10, "bold"))
        frame2.pack(fill="x", padx=15, pady=10)
        
        output_frame = tk.Frame(frame2)
        output_frame.pack(fill="x", padx=10, pady=5)
        tk.Entry(output_frame, textvariable=self.output_file, font=("Arial", 9)).pack(side="left", fill="x", expand=True)
        tk.Button(output_frame, text="Save As", command=self.select_output, 
                 width=10, bg="#2ecc71", fg="white").pack(side="right", padx=(5,0))
        
        # Method selection
        frame3 = tk.LabelFrame(parent, text="Steganography Method", font=("Arial", 10, "bold"))
        frame3.pack(fill="x", padx=15, pady=10)
        
        method_frame = tk.Frame(frame3)
        method_frame.pack(fill="x", padx=10, pady=5)
        
        methods = [
            ("EXIF Embedding (JPEG files)", "exif"),
            ("LSB Steganography (PNG/BMP files)", "lsb"),
            ("Filename Polyglot (Universal format)", "polyglot"),
            ("PNG Comment Embedding", "png_comment")
        ]
        
        for text, value in methods:
            tk.Radiobutton(method_frame, text=text, variable=self.method, 
                          value=value, font=("Arial", 9)).pack(anchor="w", pady=2)
        
        # Encryption
        frame4 = tk.LabelFrame(parent, text="Encryption", font=("Arial", 10, "bold"))
        frame4.pack(fill="x", padx=15, pady=10)
        
        tk.Checkbutton(frame4, text="Use encryption", variable=self.use_encryption, 
                      font=("Arial", 9), command=self.toggle_encryption).pack(anchor="w", padx=10, pady=5)
        
        self.enc_frame = tk.Frame(frame4)
        self.enc_frame.pack(fill="x", padx=10)
        
        enc_method_frame = tk.Frame(self.enc_frame)
        enc_method_frame.pack(fill="x", pady=5)
        tk.Label(enc_method_frame, text="Method:", font=("Arial", 9)).pack(anchor="w")
        
        enc_methods = [
            ("AES-256 Encryption", "aes"),
            ("XOR Encryption", "xor"),
            ("Multi-Layer (AES + XOR)", "multi")
        ]
        
        for text, value in enc_methods:
            tk.Radiobutton(enc_method_frame, text=text, variable=self.encryption, 
                          value=value, font=("Arial", 9)).pack(anchor="w")
        
        key_frame = tk.Frame(self.enc_frame)
        key_frame.pack(fill="x", pady=5)
        tk.Label(key_frame, text="Password:", font=("Arial", 9)).pack(anchor="w")
        tk.Entry(key_frame, textvariable=self.password, show="*", font=("Arial", 9)).pack(fill="x")
        
        self.toggle_encryption()
        
        # Hide button
        tk.Button(parent, text="HIDE PAYLOAD", command=self.hide_payload,
                 bg="#e74c3c", fg="white", font=("Arial", 11, "bold"), height=2).pack(fill="x", padx=15, pady=15)
        
        # Status
        self.embed_status = tk.Label(parent, text="Ready to hide payload", fg="gray")
        self.embed_status.pack(side="bottom", fill="x", padx=15, pady=5)
        
    def create_extract_tab(self, parent):
        # Input file
        frame1 = tk.LabelFrame(parent, text="Stego File", font=("Arial", 10, "bold"))
        frame1.pack(fill="x", padx=15, pady=10)
        
        file_frame = tk.Frame(frame1)
        file_frame.pack(fill="x", padx=10, pady=5)
        tk.Entry(file_frame, textvariable=self.extract_input, font=("Arial", 9)).pack(side="left", fill="x", expand=True)
        tk.Button(file_frame, text="Browse", command=self.select_extract_input, 
                 width=10, bg="#3498db", fg="white").pack(side="right", padx=(5,0))
        
        # Output file
        frame2 = tk.LabelFrame(parent, text="Extracted File", font=("Arial", 10, "bold"))
        frame2.pack(fill="x", padx=15, pady=10)
        
        output_frame = tk.Frame(frame2)
        output_frame.pack(fill="x", padx=10, pady=5)
        tk.Entry(output_frame, textvariable=self.extract_output, font=("Arial", 9)).pack(side="left", fill="x", expand=True)
        tk.Button(output_frame, text="Save As", command=self.select_extract_output, 
                 width=10, bg="#2ecc71", fg="white").pack(side="right", padx=(5,0))
        
        # Method selection
        frame3 = tk.LabelFrame(parent, text="Extraction Method", font=("Arial", 10, "bold"))
        frame3.pack(fill="x", padx=15, pady=10)
        
        method_frame = tk.Frame(frame3)
        method_frame.pack(fill="x", padx=10, pady=5)
        
        methods = [
            ("Auto-detect method", "auto"),
            ("EXIF extraction", "exif"),
            ("LSB extraction", "lsb"),
            ("Polyglot extraction", "polyglot"),
            ("PNG Comment extraction", "png_comment")
        ]
        
        for text, value in methods:
            tk.Radiobutton(method_frame, text=text, variable=tk.StringVar(value="auto"), 
                          value=value, font=("Arial", 9)).pack(anchor="w", pady=2)
        
        # Password
        frame4 = tk.LabelFrame(parent, text="Decryption Password", font=("Arial", 10, "bold"))
        frame4.pack(fill="x", padx=15, pady=10)
        
        key_frame = tk.Frame(frame4)
        key_frame.pack(fill="x", padx=10, pady=5)
        tk.Entry(key_frame, textvariable=tk.StringVar(), show="*", font=("Arial", 9)).pack(fill="x")
        
        # Extract button
        tk.Button(parent, text="EXTRACT PAYLOAD", command=self.extract_payload,
                 bg="#3498db", fg="white", font=("Arial", 11, "bold"), height=2).pack(fill="x", padx=15, pady=15)
        
        # Status
        self.extract_status = tk.Label(parent, text="Ready to extract payload", fg="gray")
        self.extract_status.pack(side="bottom", fill="x", padx=15, pady=5)
        
    def create_encrypt_tab(self, parent):
        # Input file
        frame1 = tk.LabelFrame(parent, text="Input File", font=("Arial", 10, "bold"))
        frame1.pack(fill="x", padx=15, pady=10)
        
        file_frame = tk.Frame(frame1)
        file_frame.pack(fill="x", padx=10, pady=5)
        tk.Entry(file_frame, textvariable=self.encrypt_input, font=("Arial", 9)).pack(side="left", fill="x", expand=True)
        tk.Button(file_frame, text="Browse", command=lambda: self.select_file(self.encrypt_input), 
                 width=10, bg="#3498db", fg="white").pack(side="right", padx=(5,0))
        
        # Output file
        frame2 = tk.LabelFrame(parent, text="Output File", font=("Arial", 10, "bold"))
        frame2.pack(fill="x", padx=15, pady=10)
        
        output_frame = tk.Frame(frame2)
        output_frame.pack(fill="x", padx=10, pady=5)
        tk.Entry(output_frame, textvariable=self.encrypt_output, font=("Arial", 9)).pack(side="left", fill="x", expand=True)
        tk.Button(output_frame, text="Save As", command=lambda: self.select_save_file(self.encrypt_output), 
                 width=10, bg="#2ecc71", fg="white").pack(side="right", padx=(5,0))
        
        # Operation
        frame3 = tk.LabelFrame(parent, text="Operation", font=("Arial", 10, "bold"))
        frame3.pack(fill="x", padx=15, pady=10)
        
        op_frame = tk.Frame(frame3)
        op_frame.pack(fill="x", padx=10, pady=5)
        tk.Radiobutton(op_frame, text="Encrypt file", variable=self.encrypt_operation, 
                      value="encrypt", font=("Arial", 9)).pack(anchor="w")
        tk.Radiobutton(op_frame, text="Decrypt file", variable=self.encrypt_operation, 
                      value="decrypt", font=("Arial", 9)).pack(anchor="w")
        
        # Encryption method
        frame4 = tk.LabelFrame(parent, text="Encryption Method", font=("Arial", 10, "bold"))
        frame4.pack(fill="x", padx=15, pady=10)
        
        method_frame = tk.Frame(frame4)
        method_frame.pack(fill="x", padx=10, pady=5)
        
        methods = [
            ("AES-256 Encryption", "aes"),
            ("XOR Encryption", "xor"),
            ("Multi-Layer Encryption", "multi")
        ]
        
        for text, value in methods:
            tk.Radiobutton(method_frame, text=text, variable=self.encryption, 
                          value=value, font=("Arial", 9)).pack(anchor="w")
        
        # Password
        frame5 = tk.LabelFrame(parent, text="Password", font=("Arial", 10, "bold"))
        frame5.pack(fill="x", padx=15, pady=10)
        
        key_frame = tk.Frame(frame5)
        key_frame.pack(fill="x", padx=10, pady=5)
        tk.Entry(key_frame, textvariable=self.password, show="*", font=("Arial", 9)).pack(fill="x")
        
        # Process button
        tk.Button(parent, text="PROCESS FILE", command=self.process_file,
                 bg="#27ae60", fg="white", font=("Arial", 11, "bold"), height=2).pack(fill="x", padx=15, pady=15)
        
        # Status
        self.encrypt_status = tk.Label(parent, text="Ready to process file", fg="gray")
        self.encrypt_status.pack(side="bottom", fill="x", padx=15, pady=5)
        
    def create_settings_tab(self, parent):
        tk.Label(parent, text="Advanced Settings", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Polymorphic settings
        frame1 = tk.LabelFrame(parent, text="Advanced Features", font=("Arial", 11, "bold"))
        frame1.pack(fill="x", padx=15, pady=10)
        
        tk.Checkbutton(frame1, text="Enable polymorphic embedding", variable=self.polymorph, 
                      font=("Arial", 10)).pack(anchor="w", padx=10, pady=5)
        tk.Checkbutton(frame1, text="Enable stealth mode", variable=self.stealth_mode, 
                      font=("Arial", 10)).pack(anchor="w", padx=10, pady=5)
        
        # Info
        info_frame = tk.Frame(parent)
        info_frame.pack(fill="x", padx=15, pady=20)
        tk.Label(info_frame, text="Professional Steganography Tool", font=("Arial", 10, "bold")).pack()
        tk.Label(info_frame, text="Author: CFS", fg="gray").pack()
        tk.Label(info_frame, text="Channel: https://t.me/cryptfileservice", fg="gray").pack()
        
    def toggle_encryption(self):
        if self.use_encryption.get():
            self.enc_frame.pack(fill="x", padx=10)
        else:
            self.enc_frame.pack_forget()
            
    def select_payload(self):
        file = filedialog.askopenfilename()
        if file: 
            self.payload_file.set(file)
            self.embed_status.config(text=f"Selected: {os.path.basename(file)}")
            
    def select_output(self):
        method = self.method.get()
        extensions = {"exif": ".jpg", "lsb": ".png", "polyglot": ".poly", "png_comment": ".png"}
        default_ext = extensions.get(method, ".*")
        file = filedialog.asksaveasfilename(defaultextension=default_ext)
        if file: 
            self.output_file.set(file)
            self.embed_status.config(text=f"Will save as: {os.path.basename(file)}")
            
    def select_extract_input(self):
        file = filedialog.askopenfilename()
        if file: 
            self.extract_input.set(file)
            self.extract_status.config(text=f"Selected: {os.path.basename(file)}")
            
    def select_extract_output(self):
        file = filedialog.asksaveasfilename()
        if file: 
            self.extract_output.set(file)
            self.extract_status.config(text=f"Will save as: {os.path.basename(file)}")
            
    def select_file(self, var):
        file = filedialog.askopenfilename()
        if file: var.set(file)
            
    def select_save_file(self, var):
        file = filedialog.asksaveasfilename()
        if file: var.set(file)
            
    # Encryption methods
    def aes_encrypt(self, data, password):
        password = password.encode() if isinstance(password, str) else password
        salt = b'salt_123'
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        return f.encrypt(data)
    
    def aes_decrypt(self, data, password):
        password = password.encode() if isinstance(password, str) else password
        salt = b'salt_123'
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        return f.decrypt(data)
    
    def xor_encrypt(self, data, key):
        if isinstance(key, str):
            key = sum(ord(c) for c in key) % 256
        return bytes([b ^ key for b in data])
    
    def multi_layer_encrypt(self, data, password):
        # Layer 1: XOR
        layer1 = self.xor_encrypt(data, password)
        # Layer 2: AES
        layer2 = self.aes_encrypt(layer1, password)
        # Layer 3: XOR again
        layer3 = self.xor_encrypt(layer2, password[::-1])
        return layer3
    
    def multi_layer_decrypt(self, data, password):
        # Layer 3: XOR decrypt
        layer3 = self.xor_encrypt(data, password[::-1])
        # Layer 2: AES decrypt
        layer2 = self.aes_decrypt(layer3, password)
        # Layer 1: XOR decrypt
        layer1 = self.xor_encrypt(layer2, password)
        return layer1
    
    def encrypt_payload(self, data):
        if not self.use_encryption.get():
            return data
        method = self.encryption.get()
        key = self.password.get()
        if method == "aes":
            return self.aes_encrypt(data, key)
        elif method == "xor":
            return self.xor_encrypt(data, key)
        elif method == "multi":
            return self.multi_layer_encrypt(data, key)
        else:
            return self.aes_encrypt(data, key)
    
    def decrypt_payload(self, data, password, method):
        try:
            if method == "aes":
                return self.aes_decrypt(data, password)
            elif method == "xor":
                return self.xor_encrypt(data, password)
            elif method == "multi":
                return self.multi_layer_decrypt(data, password)
            else:
                return self.aes_decrypt(data, password)
        except:
            return data
    
    # Steganography methods
    def embed_exif(self, payload_data, output_path):
        """EXIF embedding"""
        try:
            # Create base image
            img = Image.new("RGB", (300, 300), color="gray")
            temp_path = "temp.jpg"
            img.save(temp_path)
            
            # Embed in EXIF
            exif_dict = {"0th": {piexif.ImageIFD.Make: payload_data}}
            exif_bytes = piexif.dump(exif_dict)
            
            img = Image.open(temp_path)
            img.save(output_path, exif=exif_bytes)
            os.remove(temp_path)
            return True
        except Exception as e:
            return False
    
    def embed_lsb(self, payload_data, output_path):
        """LSB steganography"""
        try:
            # Convert payload to bits
            payload_bits = ''.join(format(byte, '08b') for byte in payload_data)
            
            # Create image
            width, height = 400, 400
            img = Image.new("RGB", (width, height), color="white")
            pixels = img.load()
            
            # Embed bits
            bit_index = 0
            for y in range(height):
                for x in range(width):
                    if bit_index >= len(payload_bits):
                        break
                    r, g, b = pixels[x, y]
                    r = (r & 0xFE) | int(payload_bits[bit_index])
                    pixels[x, y] = (r, g, b)
                    bit_index += 1
                if bit_index >= len(payload_bits):
                    break
            
            img.save(output_path, format="PNG")
            return True
        except Exception as e:
            return False
    
    def hide_payload(self):
        try:
            # Read payload
            with open(self.payload_file.get(), "rb") as f:
                payload_data = f.read()
            
            # Encrypt if needed
            payload_data = self.encrypt_payload(payload_data)
            
            # Add polymorphic marker if enabled
            if self.polymorph.get():
                marker = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))
                payload_data = f"POLY_{marker}_".encode() + payload_data
            
            # Embed using selected method
            method = self.method.get()
            success = False
            
            if method == "exif":
                success = self.embed_exif(payload_data, self.output_file.get())
            elif method == "lsb":
                success = self.embed_lsb(payload_data, self.output_file.get())
            elif method == "polyglot":
                with open(self.output_file.get(), "wb") as f:
                    f.write(b"POLYGLOT_FILE" + payload_data)
                success = True
            elif method == "png_comment":
                img = Image.new("RGB", (300, 300), color="gray")
                img.save(self.output_file.get(), format="PNG")
                with open(self.output_file.get(), "ab") as f:
                    f.write(b"PNG_COMMENT" + payload_data)
                success = True
            
            if success:
                self.embed_status.config(text=f"Success! Hidden {len(payload_data)} bytes")
                messagebox.showinfo("Success", f"Payload hidden successfully!\nSize: {len(payload_data)} bytes")
            else:
                raise Exception("Embedding failed")
                
        except Exception as e:
            self.embed_status.config(text="Error occurred")
            messagebox.showerror("Error", str(e))
    
    def extract_exif(self, input_path):
        """EXIF extraction"""
        try:
            img = Image.open(input_path)
            exif_dict = piexif.load(img.info.get("exif", b""))
            return exif_dict["0th"].get(piexif.ImageIFD.Make)
        except:
            return None
    
    def extract_lsb(self, input_path):
        """LSB extraction"""
        try:
            img = Image.open(input_path)
            pixels = img.load()
            width, height = img.size
            
            # Extract bits
            bits = []
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]
                    bits.append(str(r & 1))
            
            # Convert to bytes
            bit_string = ''.join(bits)
            payload_bytes = bytearray()
            for i in range(0, len(bit_string), 8):
                if i + 8 <= len(bit_string):
                    byte = bit_string[i:i+8]
                    payload_bytes.append(int(byte, 2))
            
            return bytes(payload_bytes)
        except:
            return None
    
    def extract_payload(self):
        try:
            input_path = self.extract_input.get()
            method = "auto"  # For now, auto-detect
            
            payload_data = None
            
            # Try all methods
            if method == "auto":
                payload_data = self.extract_exif(input_path)
                if not payload_data:
                    payload_data = self.extract_lsb(input_path)
                if not payload_data:
                    # Try simple extraction
                    with open(input_path, "rb") as f:
                        data = f.read()
                        markers = [b"POLYGLOT_FILE", b"PNG_COMMENT"]
                        for marker in markers:
                            start = data.find(marker)
                            if start != -1:
                                payload_data = data[start + len(marker):]
                                break
            
            if not payload_data:
                raise Exception("No payload found")
            
            # Remove polymorphic marker if present
            if payload_data.startswith(b"POLY_") and b"_" in payload_data[5:20]:
                underscore_pos = payload_data.find(b"_", 5)
                if underscore_pos != -1:
                    payload_data = payload_data[underscore_pos + 1:]
            
            # Save extracted data
            with open(self.extract_output.get(), "wb") as f:
                f.write(payload_data)
                
            self.extract_status.config(text=f"Success! Extracted {len(payload_data)} bytes")
            messagebox.showinfo("Success", f"Payload extracted successfully!\nSize: {len(payload_data)} bytes")
            
        except Exception as e:
            self.extract_status.config(text="Error occurred")
            messagebox.showerror("Error", str(e))
    
    def process_file(self):
        try:
            input_path = self.encrypt_input.get()
            output_path = self.encrypt_output.get()
            operation = self.encrypt_operation.get()
            method = self.encryption.get()
            password = self.password.get()
            
            # Read file
            with open(input_path, "rb") as f:
                data = f.read()
            
            # Process
            if operation == "encrypt":
                if method == "aes":
                    processed_data = self.aes_encrypt(data, password)
                elif method == "xor":
                    processed_data = self.xor_encrypt(data, password)
                elif method == "multi":
                    processed_data = self.multi_layer_encrypt(data, password)
                else:
                    processed_data = self.aes_encrypt(data, password)
                
                with open(output_path, "wb") as f:
                    f.write(processed_data)
                    
                self.encrypt_status.config(text=f"Success! Encrypted {len(processed_data)} bytes")
                messagebox.showinfo("Success", f"File encrypted successfully!\nSize: {len(processed_data)} bytes")
                
            else:  # decrypt
                if method == "aes":
                    processed_data = self.aes_decrypt(data, password)
                elif method == "xor":
                    processed_data = self.xor_encrypt(data, password)
                elif method == "multi":
                    processed_data = self.multi_layer_decrypt(data, password)
                else:
                    processed_data = self.aes_decrypt(data, password)
                
                with open(output_path, "wb") as f:
                    f.write(processed_data)
                    
                self.encrypt_status.config(text=f"Success! Decrypted {len(processed_data)} bytes")
                messagebox.showinfo("Success", f"File decrypted successfully!\nSize: {len(processed_data)} bytes")
                
        except Exception as e:
            self.encrypt_status.config(text="Error occurred")
            messagebox.showerror("Error", str(e))

def main():
    if not install_dependencies():
        print("Failed to install dependencies")
        return
    root = tk.Tk()
    app = StegoTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()
