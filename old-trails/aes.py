from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def encrypt_text(text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return cipher.iv + ciphertext

def decrypt_text(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return plaintext.decode('utf-8')

def main():
    choice = input("Enter 'encrypt' to encrypt or 'decrypt' to decrypt: ").strip().lower()

    if choice == 'encrypt':
        plaintext = input("Enter the message to encrypt: ").strip()
        key = get_random_bytes(16)
        ciphertext = encrypt_text(plaintext, key)
        print("Encrypted message", ciphertext.hex())
        print("Key:", key.hex())

    elif choice == 'decrypt':
        ciphertext_hex = input("Enter the ciphertext in hexadecimal format: ").strip()
        ciphertext = bytes.fromhex(ciphertext_hex)
        key_hex = input("Enter the key in hexadecimal format: ").strip()
        key = bytes.fromhex(key_hex)
        plaintext = decrypt_text(ciphertext, key)
        print("Decrypted message:", plaintext)

    else:
        print("Invalid choice. Please enter 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()