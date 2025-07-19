import ctypes
import pytest
import os
import platform
print(f"CWD: {os.getcwd()}, Platform: {platform.system()} {platform.release()}" )
from crashshell.basemem import SecureMemory
from crashshell.windows.winmem import WindowsSecureMemory
import time
import secrets

# Alloc secure memory
mem = SecureMemory(WindowsSecureMemory, 4096)
false_bytes = secrets.token_bytes(4096)
super_secret_message = b"SUPERSECRETAPIKEY"
secret_list = ["maui", "kauii", "oahu", "big island"]
secret_dict = {"secret": "value", "another": 1234}
secret_bytes = b'byteobject'
secret_int = 42
secret_float = 3.14159
secret_tuple = (1, 2, 3)
secret_set = {4, 5, 6}
to_bytes_obj = str({"list": secret_list, "dict": secret_dict, "bytes": secret_bytes, "int": secret_int, "float": secret_float, "tuple": secret_tuple, "set": list(secret_set)}).encode('utf-8')
super_secret_message += bytes(to_bytes_obj[:4096 - len(super_secret_message)])
false_bytes = super_secret_message + false_bytes[len(super_secret_message):]
print(f"Writing secret: {super_secret_message}. Padding offset {len(super_secret_message)}")
mem.write(false_bytes)
with open("real.bin", "wb") as f:
    f.write(false_bytes)

# Force it to be protected
mem.protect()

# CRASH: Read from protected region (this is what breaks things)
ctypes.memmove(ctypes.create_string_buffer(1), ctypes.c_void_p(mem.get_ptr()), 1)