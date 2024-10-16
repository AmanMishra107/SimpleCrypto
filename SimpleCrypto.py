from Crypto.Cipher import AES, Blowfish
from Crypto.Random import get_random_bytes
import base64

# --- Step 1: Caesar Cipher Encryption ---
def caesar_encrypt(plaintext, shift):
    result = ""
    for char in plaintext:
        if char.isalpha():
            shift_char = chr((ord(char) + shift - 65) % 26 + 65) if char.isupper() else chr((ord(char) + shift - 97) % 26 + 97)
            result += shift_char
        else:
            result += char  # Non-alphabetical characters remain unchanged
    return result

# --- Step 3: AES Encryption ---
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return base64.b64encode(cipher.nonce + ciphertext).decode('utf-8')

# --- Step 4: Blowfish Encryption ---
def blowfish_encrypt(plaintext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return base64.b64encode(cipher.nonce + ciphertext).decode('utf-8')

# --- Main Execution ---
if __name__ == "__main__":
    # Input text for Caesar cipher
    plaintext = input("Enter the text you want to encrypt: ")
    shift = 3
    
    # Encrypt using Caesar Cipher
    caesar_ciphertext = caesar_encrypt(plaintext, shift)
    print(f"Caesar Encrypted Text (Shift {shift}): {caesar_ciphertext}")
    
    # AES Encryption Example
    aes_key = get_random_bytes(16)  # AES key must be 16, 24, or 32 bytes
    aes_ciphertext = aes_encrypt(plaintext, aes_key)
    print(f"\nAES Encrypted Text: {aes_ciphertext}")
    
    # Blowfish Encryption Example
    blowfish_key = get_random_bytes(16)  # Blowfish key can vary in length (4-56 bytes)
    blowfish_ciphertext = blowfish_encrypt(plaintext, blowfish_key)
    print(f"Blowfish Encrypted Text: {blowfish_ciphertext}")
