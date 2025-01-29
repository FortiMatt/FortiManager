import os
import json
import hashlib
import subprocess
import sys
from getpass import getpass

SECRETS_FILE = "secrets.json"
VENV_DIR = "venv"
REQUIREMENTS = [
    "requests",
    "reportlab"
]

def generate_key(master_password):
    """Generate a 32-byte key from the master password using SHA-256."""
    return hashlib.sha256(master_password.encode()).digest()

def xor_encrypt(data, key):
    """Encrypt data using XOR with the provided key."""
    encrypted = bytearray()
    key_len = len(key)
    for i, char in enumerate(data.encode()):
        encrypted.append(char ^ key[i % key_len])  # XOR each byte with key
    return encrypted.hex()  # Convert to hex for easy storage

def validate_smtp_security(security):
    """Ensure valid SMTP security input (TLS, SSL, NONE)."""
    valid_options = {"TLS", "SSL", "NONE"}
    return security.strip().upper() if security.strip().upper() in valid_options else "TLS"

def get_user_input(prompt_text, is_password=False):
    """Generic input function to handle password masking."""
    return getpass(prompt_text) if is_password else input(prompt_text).strip()

def prompt_user():
    """Prompt user for FortiManager & SMTP configuration details."""
    print("\n[🔧] Setup Configuration for FortiManager & SMTP")

    return {
        "fortimanager_ip": get_user_input("Enter FortiManager IP (Default: 127.0.0.1): ") or "127.0.0.1",
        "fortimanager_username": get_user_input("Enter FortiManager Username: "),
        "fortimanager_password": get_user_input("Enter FortiManager Password: ", is_password=True),
        "adom": get_user_input("Enter ADOM (leave blank for 'root'): ") or "root",
        "smtp_server": get_user_input("Enter SMTP Server: "),
        "smtp_port": get_user_input("Enter SMTP Port (Default: 587 for TLS, 465 for SSL): ") or "587",
        "smtp_security": validate_smtp_security(get_user_input("Enter SMTP Security (TLS/SSL/NONE): ")),
        "smtp_username": get_user_input("Enter SMTP Username: "),
        "smtp_password": get_user_input("Enter SMTP Password: ", is_password=True),
        "smtp_email_to": get_user_input("Enter Email Recipient: "),
        "ports": get_user_input("Enter Ports to Fetch (comma-separated or ALL): ")
    }

def protect_secrets_file():
    """Ensure secrets.json file has restricted access permissions."""
    if os.name == "posix":  # Unix/Linux/macOS
        os.chmod(SECRETS_FILE, 0o600)  # Owner read/write only
    elif os.name == "nt":  # Windows
        os.system(f"icacls {SECRETS_FILE} /inheritance:r > nul 2>&1")

def save_secrets():
    """Encrypt user secrets and save them to a file."""
    print("\n[!] You will be asked to set a password to encrypt the secrets.")

    while True:
        master_password = getpass("Set a password to encrypt secrets: ")
        confirm_password = getpass("Confirm your password: ")
        if master_password == confirm_password:
            break
        print("[-] Passwords do not match. Please try again.")

    key = generate_key(master_password)  # Generate encryption key
    secrets_data = prompt_user()

    # Encrypt each secret using XOR
    encrypted_data = {k: xor_encrypt(v, key) for k, v in secrets_data.items()}

    with open(SECRETS_FILE, "w") as f:
        json.dump(encrypted_data, f, indent=4)

    protect_secrets_file()  # Restrict file access
    print("\n[✅] Secrets saved securely in", SECRETS_FILE)
    print("[🔒] File permissions restricted for security.")
    print("[!] Remember your password, as it is required to decrypt the secrets.")

def create_virtual_env():
    """Create and activate a virtual environment."""
    if not os.path.exists(VENV_DIR):
        print(f"\n[🔄] Creating virtual environment: {VENV_DIR}...")
        subprocess.run([sys.executable, "-m", "venv", VENV_DIR], check=True)
        print("[✅] Virtual environment created.")

def install_requirements():
    """Install necessary Python libraries inside the virtual environment."""
    pip_path = os.path.join(VENV_DIR, "bin", "pip") if os.name != "nt" else os.path.join(VENV_DIR, "Scripts", "pip.exe")

    print("\n[🔄] Installing required libraries...")
    subprocess.run([pip_path, "install"] + REQUIREMENTS, check=True)
    print("[✅] Required libraries installed.")

def activate_virtual_env():
    """Provide instructions to activate the virtual environment."""
    print("\n[💡] Virtual environment setup complete.")
    if os.name == "posix":  # Linux/macOS
        print(f"[🟢] To activate, run: source {VENV_DIR}/bin/activate")
    elif os.name == "nt":  # Windows
        print(f"[🟢] To activate, run: {VENV_DIR}\\Scripts\\activate")

def setup():
    """Run full setup: save secrets, create virtual env, install libraries."""
    save_secrets()
    create_virtual_env()
    install_requirements()
    activate_virtual_env()

if __name__ == "__main__":
    setup()
