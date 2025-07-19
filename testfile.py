with open("dump.bin", "rb") as f:
    data = f.read()

byte_set = set(data)
print(f"Unique bytes in dump.bin: {sorted(byte_set)}")
byte_index_set = set()
for byte_index, byte in enumerate(data):
    byte_index_set.add(byte)

print(f"Unique byte values: {sorted(byte_set)}")
print(f"Unique byte values count: {len(byte_set)}")
print(f"Total bytes read: {len(data)}")

with open("real.bin", "rb") as f:
    real_data = f.read()

real_byte_set = set(real_data)
print(f"Unique bytes in real.bin: {sorted(real_byte_set)}")
byte_index_set_real = set()
for byte_index, byte in enumerate(real_data):
    byte_index_set_real.add(byte)

print(f"Unique byte values in real.bin: {sorted(real_byte_set)}")
print(f"Unique byte values count in real.bin: {len(real_byte_set)}")
print(f"Total bytes read in real.bin: {len(real_data)}")