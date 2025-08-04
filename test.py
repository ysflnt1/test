import os
import json
import base64
import sqlite3
import shutil
import win32crypt
from Crypto.Cipher import AES
import tempfile

# --- CONFIGURATION ---

LOCAL_STATE_PATH = os.path.join(
    os.environ['LOCALAPPDATA'], "Google", "Chrome", "User Data", "Local State"
)
LOGIN_DATA_PATH = os.path.join(
    os.environ['LOCALAPPDATA'], "Google", "Chrome", "User Data", "Default", "Login Data"
)

# --- AES KEY HANDLING ---

def get_encryption_key():
    with open(LOCAL_STATE_PATH, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
    encrypted_key = base64.b64decode(encrypted_key_b64)[5:]  # Remove DPAPI prefix
    decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return decrypted_key

# --- DECRYPTION LOGIC ---

def decrypt_password(encrypted_password, key):
    try:
        if encrypted_password[:3] == b'v10':
            iv = encrypted_password[3:15]
            payload = encrypted_password[15:-16]
            tag = encrypted_password[-16:]

            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            decrypted_pass = cipher.decrypt_and_verify(payload, tag)
            return decrypted_pass.decode('utf-8')
        else:
            # Older format (rare in Chrome 80+)
            return win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode('utf-8')
    except Exception as e:
        return f"[Decryption failed: {e}]"

# --- DATABASE HANDLING ---

def extract_passwords():
    key = get_encryption_key()
    
    # Work on a temp copy of the DB to avoid Chrome lock
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        shutil.copy2(LOGIN_DATA_PATH, tmp.name)
        db_path = tmp.name

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

    print("Recovered Chrome Passwords:\n" + "-"*50)
    for origin_url, username, encrypted_password in cursor.fetchall():
        if not username and not encrypted_password:
            continue
        decrypted_password = decrypt_password(encrypted_password, key)
        print(f"URL: {origin_url}")
        print(f"User: {username}")
        print(f"Pass: {decrypted_password}")
        print("-" * 50)

    cursor.close()
    conn.close()
    os.remove(db_path)

# --- MAIN ENTRY ---

if __name__ == "__main__":
    extract_passwords()
