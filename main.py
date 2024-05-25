from aes import *
from gui import *

def main():
    choice = int(input("Enter '0' to encrypt or '1' to decrypt: ").strip().lower())

    if choice == 0:
        filepath = filedialog.askopenfilename()
        if not os.path.exists(filepath):
            print("File not found.")
            return

        with open(filepath, 'rb') as f:
            file_data = f.read()

        key = secrets.token_bytes(16)
        print("Generated encryption key:", key.hex())
        pyperclip.copy(key.hex())

        if len(file_data) % 16 != 0:
            file_data += b'\0' * (16 - len(file_data) % 16)

        encrypted_data = bytearray()
        for i in range(0, len(file_data), 16):
            block = file_data[i:i+16]
            encrypted_block = encrypt_block(block, key)
            encrypted_data.extend(encrypted_block)

        print("Encryption complete.")

        with open(filepath, 'wb') as f:
            f.write(encrypted_data)

        print(f"Encrypted file saved to {filepath}")

    elif choice == 1:
        filepath = filedialog.askopenfilename()
        if not os.path.exists(filepath):
            print("File not found.")
            return

        key_hex = input("Enter the encryption key: ").strip()
        key = bytes.fromhex(key_hex)

        with open(filepath, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = bytearray()
        for i in range(0, len(encrypted_data), 16):
            block = encrypted_data[i:i+16]
            decrypted_block = decrypt_block(block, key)
            decrypted_data.extend(decrypted_block)

        print("Decryption complete.")
 
        with open(filepath, 'wb') as f:
            f.write(decrypted_data.rstrip(b'\0'))

        print(f"Decrypted file saved to {filepath}")

    else:
        print("Invalid choice. Please enter 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()