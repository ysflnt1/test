import ctypes
import psutil
import re

# Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04

# Memory info structure for VirtualQueryEx
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_ulong),
                ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.c_ulong),
                ("Protect", ctypes.c_ulong),
                ("Type", ctypes.c_ulong)]

# Get PID of chrome.exe
def get_chrome_pid():
    for proc in psutil.process_iter(['name']):
        try:
            if 'chrome.exe' in proc.info['name'].lower():
                return proc.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None

# Open Chrome process
def open_process(pid):
    return ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)

# Enumerate readable memory regions
def enum_memory_regions(process_handle):
    address = 0
    mem_info = MEMORY_BASIC_INFORMATION()
    while ctypes.windll.kernel32.VirtualQueryEx(
        process_handle,
        ctypes.c_void_p(address),
        ctypes.byref(mem_info),
        ctypes.sizeof(mem_info)
    ):
        if mem_info.State == MEM_COMMIT and mem_info.Protect & PAGE_READWRITE:
            yield (mem_info.BaseAddress, mem_info.RegionSize)
        address += mem_info.RegionSize

# Read memory block
def read_memory(process_handle, base_address, size):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    if ctypes.windll.kernel32.ReadProcessMemory(
        process_handle,
        ctypes.c_void_p(base_address),
        buffer,
        size,
        ctypes.byref(bytes_read)
    ):
        return buffer.raw[:bytes_read.value]
    return None

# Extract UTF-16LE strings with 2+ characters
def find_utf16le_strings(data, min_len=2):
    # UTF-16LE pattern: printable ASCII chars with nulls, at least 2 characters
    pattern = re.compile(b'(?:[\x20-\x7E]\x00){' + str(min_len).encode() + b',}')
    found = []
    for match in pattern.finditer(data):
        try:
            s = match.group().decode('utf-16le')
            found.append(s)
        except UnicodeDecodeError:
            continue
    return found

def main():
    pid = get_chrome_pid()
    if not pid:
        print("Chrome process not found.")
        return

    print(f"[+] Found Chrome PID: {pid}")
    process_handle = open_process(pid)
    if not process_handle:
        print("[-] Failed to open Chrome process. Run as admin?")
        return

    print("[*] Scanning memory...")
    seen = set()
    for base_addr, region_size in enum_memory_regions(process_handle):
        data = read_memory(process_handle, base_addr, region_size)
        if data:
            strings = find_utf16le_strings(data)
            for s in strings:
                # Avoid duplicates
                if s not in seen:
                    seen.add(s)
                    print(s)

    ctypes.windll.kernel32.CloseHandle(process_handle)
    print("[+] Done.")

if __name__ == "__main__":
    main()
