import os
import json
from cryptography.fernet import Fernet

CONFIG_FILE = "config.json"  # Original config file
ENCRYPTED_FILE = "config.enc"  # Encrypted file
KEY_FILE = "key.key"  # File to store the encryption key

def generate_key():
    """
    Generate a new encryption key and save it to a file.
    """
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    print(f"Encryption key saved to {KEY_FILE}")

def load_key():
    """
    Load the encryption key from a file.
    """
    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError("Encryption key file not found. Please generate a key first.")
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

def encrypt_config():
    """
    Encrypt the configuration file using the encryption key.
    """
    key = load_key()
    fernet = Fernet(key)

    # Read the config file
    with open(CONFIG_FILE, "rb") as f:
        data = f.read()

    # Encrypt the file
    encrypted_data = fernet.encrypt(data)
    with open(ENCRYPTED_FILE, "wb") as f:
        f.write(encrypted_data)

    print(f"Config file encrypted and saved to {ENCRYPTED_FILE}")

def decrypt_config():
    """
    Decrypt the encrypted configuration file and save the output.
    """
    key = load_key()
    fernet = Fernet(key)

    # Read the encrypted file
    with open(ENCRYPTED_FILE, "rb") as f:
        encrypted_data = f.read()

    # Decrypt the file
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(CONFIG_FILE, "wb") as f:
        f.write(decrypted_data)

    print(f"Config file decrypted and saved to {CONFIG_FILE}")

if __name__ == "__main__":
    print("1. Generate a new key")
    print("2. Encrypt the config file")
    print("3. Decrypt the config file")
    choice = input("Choose an option: ")

    if choice == "1":
        generate_key()
    elif choice == "2":
        encrypt_config()
    elif choice == "3":
        decrypt_config()
    else:
        print("Invalid choice.")
