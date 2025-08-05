import os
import json
import base64
import sqlite3
import shutil
import win32crypt
from Cryptodome.Cipher import AES
from datetime import datetime, timedelta

# Step 1: Get paths
local_state_path = os.path.join(
    os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data\Local State")
login_data_path = os.path.join(
    os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data\Default\Login Data")

# Step 2: Get AES key from Local State
with open(local_state_path, "r", encoding="utf-8") as f:
    local_state = json.load(f)
encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
encrypted_key = base64.b64decode(encrypted_key_b64)[5:]  # remove 'DPAPI' prefix

# Decrypt with DPAPI
decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

# Step 3: Copy DB (Chrome locks it while running)
tmp_db = "Loginvault.db"
shutil.copy2(login_data_path, tmp_db)

# Step 4: Open DB and decrypt passwords
conn = sqlite3.connect(tmp_db)
cursor = conn.cursor()

cursor.execute("""
SELECT origin_url, username_value, password_value, date_created
FROM logins
""")

def decrypt_password(buff, key):
    try:
        if buff.startswith(b'v10') or buff.startswith(b'v11'):
            iv = buff[3:15]
            payload = buff[15:-16]
            tag = buff[-16:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt_and_verify(payload, tag)
            return decrypted.decode('utf-8')
        else:
            return win32crypt.CryptUnprotectData(buff, None, None, None, 0)[1].decode()
    except Exception as e:
        return f"[Decryption failed] {e}"

print("\n🟢 Decrypted Chrome Passwords:\n")

for row in cursor.fetchall():
    origin_url = row[0]
    username = row[1]
    encrypted_password = row[2]
    created = row[3]

    if not username and not encrypted_password:
        continue

    password = decrypt_password(encrypted_password, decrypted_key)

    if created:
        created_time = datetime(1601, 1, 1) + timedelta(microseconds=created)
        created_str = created_time.strftime("%Y-%m-%d %H:%M:%S")
    else:
        created_str = "N/A"

    print(f"🔹 URL: {origin_url}")
    print(f"   Username: {username}")
    print(f"   Password: {password}")
    print(f"   Created: {created_str}\n")

conn.close()
os.remove(tmp_db)
