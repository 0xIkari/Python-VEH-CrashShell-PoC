import ctypes
from ctypes import wintypes
import threading
from . import wincrash

class WindowsSecureMemory:
    __slots__ = ("size", "k32", "_lock", "addr", "requested_size", "aligned_size", "protected", "closed"
                 , "PAGE_NOACCESS", "PAGE_READWRITE", "MEM_COMMIT", "MEM_RESERVE", "MEM_RELEASE")

    def __init__(self, size: int):
        self.size = size
        self.k32 = ctypes.windll.kernel32
        self._lock = threading.RLock()

        self.PAGE_NOACCESS = 0x01
        self.PAGE_READWRITE = 0x04
        self.MEM_COMMIT = 0x1000
        self.MEM_RESERVE = 0x2000
        self.MEM_RELEASE = 0x8000

        class SYSTEM_INFO(ctypes.Structure):
            _fields_ = [
                ("wProcessorArchitecture", wintypes.WORD),
                ("wReserved", wintypes.WORD),
                ("dwPageSize", wintypes.DWORD),
                ("lpMinimumApplicationAddress", ctypes.c_void_p),
                ("lpMaximumApplicationAddress", ctypes.c_void_p),
                ("dwActiveProcessorMask", ctypes.c_void_p),
                ("dwNumberOfProcessors", wintypes.DWORD),
                ("dwProcessorType", wintypes.DWORD),
                ("dwAllocationGranularity", wintypes.DWORD),
                ("wProcessorLevel", wintypes.WORD),
                ("wProcessorRevision", wintypes.WORD),
            ]
        sys_info = SYSTEM_INFO()
        self.k32.GetSystemInfo(ctypes.byref(sys_info))
        page_size = sys_info.dwPageSize
        aligned_size = ((self.size + page_size - 1) // page_size) * page_size
        self.requested_size = self.size
        self.aligned_size = aligned_size
        self.k32.VirtualAlloc.restype = ctypes.c_void_p
        self.k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]

        self.k32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        self.k32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

        self.k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
        self.k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(wintypes.DWORD)]
        self.addr = self.k32.VirtualAlloc(
            None,
            ctypes.c_size_t(self.aligned_size),
            self.MEM_COMMIT | self.MEM_RESERVE,
            self.PAGE_READWRITE
        )
        if not self.addr:
            raise MemoryError(f"VirtualAlloc failed: {self.k32.GetLastError()} {ctypes.FormatError(self.k32.GetLastError())}")
        if self.addr % page_size != 0:
            raise MemoryError(f"VirtualAlloc returned non-page-aligned address: {hex(self.addr)}")


        if not self.k32.VirtualLock(ctypes.c_void_p(self.addr), ctypes.c_size_t(self.aligned_size)):
            err = self.k32.GetLastError()
            raise MemoryError(f"VirtualLock failed: {err} {ctypes.FormatError(err)}")
        wincrash.register_region(self.addr, self.aligned_size)
        self.protected = False
        self.closed = False

    def write(self, data: bytes):
        with self._lock:
            if self.protected:
                raise RuntimeError("Memory is protected")
            if self.closed:
                raise RuntimeError("Memory is closed")
            if len(data) > self.size:
                raise ValueError("Data exceeds allocated buffer")
            ctypes.memmove(self.addr, data, len(data))

    def read(self) -> bytes:
        with self._lock:
            if self.protected:
                raise RuntimeError("Memory is protected")
            if self.closed:
                raise RuntimeError("Memory is closed")
            return ctypes.string_at(self.addr, self.size)

    def protect(self):
        with self._lock:
            if self.closed:
                raise RuntimeError("Memory is closed")
            old = wintypes.DWORD()
            if not self.k32.VirtualProtect(
                ctypes.c_void_p(self.addr),
                self.size,
                self.PAGE_NOACCESS,
                ctypes.byref(old)
            ):
                raise MemoryError("VirtualProtect failed")
            self.protected = True

    def unprotect(self):
        with self._lock:
            if self.closed:
                raise RuntimeError("Memory is closed")
            old = wintypes.DWORD()
            if not self.k32.VirtualProtect(
                ctypes.c_void_p(self.addr),
                self.size,
                self.PAGE_READWRITE,
                ctypes.byref(old)
            ):
                raise MemoryError("VirtualProtect failed")
            self.protected = False

    def get_ptr(self) -> int:
        with self._lock:
            if self.closed:
                raise RuntimeError("Memory is closed")
            return self.addr

    def is_protected(self) -> bool:
        with self._lock:
            if self.closed:
                raise RuntimeError("Memory is closed")
            return self.protected

    def close(self):
        with self._lock:
            if self.closed:
                return
            self.closed = True
            try:
                self.unprotect()
            except Exception:
                pass
            ctypes.memset(self.addr, 0xAA, self.aligned_size)
            ctypes.memset(self.addr, 0x55, self.aligned_size)
            ctypes.memset(self.addr, 0x00, self.aligned_size)
            self.k32.VirtualUnlock(self.addr, self.size)
            wincrash.unregister_region(self.addr)
            self.k32.VirtualFree(self.addr, 0, self.MEM_RELEASE)
            self.addr = None