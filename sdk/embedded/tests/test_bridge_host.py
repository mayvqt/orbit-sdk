"""Local binary bridge checks; no network or credentials."""
import struct
import subprocess
import sys

def request(op, length=0):
    return struct.pack("<4sBBHHHI", b"ORB1", op, 0, 0, 0, 0, length)

proc = subprocess.run([*sys.argv[1:], "https://example.com"],
                      input=request(3) + request(4, 32) + request(4, 32),
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=True)
reply = proc.stdout
assert len(reply) == 120
for offset in (0, 40, 80):
    assert reply[offset:offset+8] == b"ORS1\0\0\0\0"
utc, elapsed = struct.unpack_from("<QQ", reply, 8)
assert utc > 0 and elapsed > 0 and any(reply[24:40])
assert reply[48:80] != reply[88:120]
print("Physical bridge host: framing, trusted clock/boot identity and CSPRNG passed")
