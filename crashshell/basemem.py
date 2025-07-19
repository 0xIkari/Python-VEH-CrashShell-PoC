class SecureMemory:
    def __init__(self, backend_cls, size: int):
        self._handler = backend_cls(size)
        self._size = size

    def write(self, data: bytes):
        return self._handler.write(data)

    def read(self) -> bytes:
        return self._handler.read()

    def protect(self):
        return self._handler.protect()

    def unprotect(self):
        return self._handler.unprotect()

    def close(self):
        return self._handler.close()

    def get_ptr(self) -> int:
        return self._handler.get_ptr()

    def is_protected(self) -> bool:
        return self._handler.is_protected()

    def __len__(self):
        return self._size

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()