import aes, os
import codecs

key = os.urandom(16)
iv = os.urandom(16)

# 'b' character before a string is used to specify the string as a “byte string“
original_text = "Hello, World!"

text_bytes = original_text.encode('utf-8')

encrypted = aes.AES(key).encrypt_ctr(text_bytes, iv)
decrypted = aes.AES(key).decrypt_ctr(encrypted, iv)

encrypted_text = encrypted
# encrypted_text = encrypted.decode('utf-8')
# encrypted_text = codecs.decode(encrypted, 'hex').decode('utf-8')
decrypted_text = decrypted.decode('utf-8')

print("Encrypted: ", encrypted)
print("Encrypted: ", encrypted_text)
print("Decrypted: ", decrypted)
print("Decrypted: ", decrypted_text)

"""

-----------------------
message:
-----------------------
hello world in JavaScript video.

-----------------------
16 bytes:
-----------------------
68 65 6c 6c
6f 20 77 6f
72 6c 64 20
69 6e 20 4a
-----------------------
61 76 61 53
63 72 69 70
74 20 76 69
64 65 6f 2e

-----------------------
32 bytes:
-----------------------
68 65 6c 6c 6f 20 77 6f
72 6c 64 20 69 6e 20 4a
61 76 61 53 63 72 69 70
74 20 76 69 64 65 6f 2e
-----------------------

"""