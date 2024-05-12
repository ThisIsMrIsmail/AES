import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pyperclip
import os

class AES_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption/Decryption")
        self.root.geometry("400x200")
        
        self.home_window()
    
    def home_window(self):
        self.frame = tk.Frame(self.root)
        self.frame.pack(pady=40)
        
        self.encrypt_button = tk.Button(self.frame, text="Encrypt", command=self.encryption_window)
        self.encrypt_button.grid(row=0, column=0, padx=10)
        
        self.decrypt_button = tk.Button(self.frame, text="Decrypt", command=self.decryption_window)
        self.decrypt_button.grid(row=0, column=1, padx=10)
    
    def encryption_window(self):
        self.frame.destroy()
        self.frame = tk.Frame(self.root)
        self.frame.pack(pady=20)
        
        self.file_label = tk.Label(self.frame, text="Select file to encrypt:")
        self.file_label.grid(row=0, column=0)
        
        self.file_entry = tk.Entry(self.frame, width=40)
        self.file_entry.grid(row=0, column=1)
        
        self.browse_button = tk.Button(self.frame, text="Browse", command=self.browse_file)
        self.browse_button.grid(row=0, column=2, padx=10)
        
        self.encrypt_button = tk.Button(self.frame, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.grid(row=1, column=1, pady=10)
    
    def decryption_window(self):
        self.frame.destroy()
        self.frame = tk.Frame(self.root)
        self.frame.pack(pady=20)
        
        self.file_label = tk.Label(self.frame, text="Select file to decrypt:")
        self.file_label.grid(row=0, column=0)
        
        self.file_entry = tk.Entry(self.frame, width=40)
        self.file_entry.grid(row=0, column=1)
        
        self.browse_button = tk.Button(self.frame, text="Browse", command=self.browse_file)
        self.browse_button.grid(row=0, column=2, padx=10)
        
        self.key_label = tk.Label(self.frame, text="Enter decryption key:")
        self.key_label.grid(row=1, column=0)
        
        self.key_entry = tk.Entry(self.frame, width=40)
        self.key_entry.grid(row=1, column=1)
        
        self.decrypt_button = tk.Button(self.frame, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.grid(row=2, column=1, pady=10)
    
    def browse_file(self):
        filename = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, filename)
    
    def encrypt_file(self):
        filename = self.file_entry.get()
        key = get_random_bytes(16)  # Generate a random 128-bit key
        aes = AES.new(key, AES.MODE_EAX)
        
        try:
            with open(filename, "rb") as file:
                plaintext = file.read()
            
            ciphertext, tag = aes.encrypt_and_digest(plaintext)
            encrypted_filename = filename + ".enc"
            with open(encrypted_filename, "wb") as file:
                [file.write(x) for x in (aes.nonce, tag, ciphertext)]
            
            pyperclip.copy(key.hex())
            messagebox.showinfo("Encryption Successful", f"File encrypted successfully!\nEncryption Key: {key.hex()}")
        except Exception as e:
            messagebox.showerror("Encryption Error", f"An error occurred during encryption:\n{str(e)}")
    
    def decrypt_file(self):
        filename = self.file_entry.get()
        key = bytes.fromhex(self.key_entry.get())
        
        try:
            with open(filename, "rb") as file:
                nonce, tag, ciphertext = [file.read(x) for x in (16, 16, -1)]
            aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
            plaintext = aes.decrypt_and_verify(ciphertext, tag)
            
            decrypted_filename = os.path.splitext(filename)[0]
            with open(decrypted_filename, "wb") as file:
                file.write(plaintext)
            
            messagebox.showinfo("Decryption Successful", "File decrypted successfully!")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"An error occurred during decryption:\n{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AES_GUI(root)
    root.mainloop()