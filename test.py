import os
import json
import base64
import sqlite3
import shutil
import win32crypt
from Crypto.Cipher import AES
import tempfile

# Paths to Chrome files
LOCAL_STATE_PATH = os.path.join(
    os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data', 'Local State'
)
LOGIN_DATA_PATH = os.path.join(
    os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data', 'Default', 'Login Data'
)

def get_encryption_key():
    """
    Extract and decrypt AES key from Local State file.
    This key is encrypted with Windows DPAPI and stored base64 encoded with 'DPAPI' prefix.
    """
    with open(LOCAL_STATE_PATH, 'r', encoding='utf-8') as f:
        local_state = json.load(f)
    encrypted_key_b64 = local_state['os_crypt']['encrypted_key']
    encrypted_key = base64.b64decode(encrypted_key_b64)[5:]  # Remove 'DPAPI' prefix
    # Decrypt key with Windows DPAPI
    decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return decrypted_key

def decrypt_password(ciphertext, key):
    """
    Decrypt a password from Chrome's encrypted blob.
    For Chrome 80+:
    - ciphertext starts with 'v10'
    - next 12 bytes = nonce (IV)
    - last 16 bytes = AES-GCM tag
    - remaining bytes in the middle = encrypted password
    """
    try:
        print(f"[DEBUG] Encrypted password prefix (hex): {ciphertext[:10].hex()}")  # Debug print
        
        if ciphertext[:3] == b'v10':
            iv = ciphertext[3:15]  # 12 bytes nonce
            payload = ciphertext[15:-16]  # encrypted data
            tag = ciphertext[-16:]  # 16 bytes tag

            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            decrypted_pass = cipher.decrypt_and_verify(payload, tag)
            return decrypted_pass.decode('utf-8')
        else:
            # Fallback for old DPAPI encrypted passwords (rare now)
            decrypted_pass = win32crypt.CryptUnprotectData(ciphertext, None, None, None, 0)[1]
            return decrypted_pass.decode('utf-8')
    except Exception as e:
        return f"[Decryption failed: {e}]"

def copy_login_db():
    """
    Copy the locked Login Data file to a temp location to avoid DB locks.
    """
    tmp_file = tempfile.NamedTemporaryFile(delete=False)
    shutil.copy2(LOGIN_DATA_PATH, tmp_file.name)
    return tmp_file.name

def main():
    key = get_encryption_key()
    db_copy = copy_login_db()
    conn = sqlite3.connect(db_copy)
    cursor = conn.cursor()
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    print("Recovered Chrome Passwords:\n" + "-"*60)
    for origin_url, username, encrypted_password in cursor.fetchall():
        if not username and not encrypted_password:
            continue
        decrypted_password = decrypt_password(encrypted_password, key)
        print(f"URL: {origin_url}")
        print(f"Username: {username}")
        print(f"Password: {decrypted_password}")
        print("-"*60)
    cursor.close()
    conn.close()
    os.remove(db_copy)

if __name__ == '__main__':
    main()
