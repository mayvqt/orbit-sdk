"""Compile/relocatable-link portable code for M0+ using installed LLVM tools.

This is a library footprint, not firmware. Crypto, TLS, board ports, compiler
runtime helpers, application data and interrupts are outside this measurement.
"""
import argparse
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
args.output.mkdir(parents=True, exist_ok=True)
objects = []
frames = {}
edges = {}
for name in ("grant", "json", "prepare", "jwks", "client", "wire", "storage"):
    obj = args.output / f"orbit_{name}.o"
    subprocess.run(["clang", "--target=arm-none-eabi", "-mcpu=cortex-m0plus", "-mthumb",
                    "-std=c11", "-Os", "-ffreestanding", "-fno-builtin", "-fstack-usage",
                    "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra",
                    "-Wpedantic", "-Werror", f"-I{root / 'include'}", "-c",
                    str(root / "src" / f"orbit_{name}.c"), "-o", str(obj)], check=True)
    objects.append(str(obj))
    for line in obj.with_suffix(".su").read_text().splitlines():
        source, size, _kind = line.split("\t")
        frames[source.rsplit(":", 1)[-1]] = int(size)
    assembly = subprocess.check_output(["llvm-objdump", "-dr", str(obj)], text=True)
    current = None
    for line in assembly.splitlines():
        match = re.match(r"[0-9a-f]+ <([^>]+)>:", line)
        if match:
            current = match.group(1)
            edges.setdefault(current, set())
        call = re.search(r"R_ARM_THM_(?:CALL|JUMP24)\s+(\S+)", line)
        if call and current:
            edges[current].add(call.group(1))

for name, group in (("core", objects[:4]), ("client", objects)):
    out = args.output / f"{name}.o"
    subprocess.run(["ld.lld", "-r", *group, "-o", str(out)], check=True)
    subprocess.run(["llvm-size", str(out)], check=True)

# Include portable callbacks invoked by services, while excluding the service's
# own frames. Actual platform stack must be measured and added by the integrator.
edges.setdefault("fetch_keys", set()).add("receive_keys")
edges.setdefault("save", set()).add("orbit_journal_commit")

def peak(name, path=()):
    if name not in frames:
        return (0, ())
    count = path.count(name)
    if count >= (16 if name == "orbit_json_skip_value" else 1):
        return (0, ())
    following = max((peak(child, path + (name,)) for child in edges.get(name, ())),
                    default=(0, ()))
    return (frames[name] + following[0], (name,) + following[1])

for name in ("orbit_grant_verify", "orbit_jwks_import", "orbit_client_activate",
             "orbit_client_require_access", "orbit_client_deactivate"):
    size, path = peak(name)
    print(f"Conservative portable stack {name}: {size} bytes; {' -> '.join(path)}")
print("Unresolved target runtime (must be supplied by the actual board toolchain):")
subprocess.run(["llvm-nm", "--undefined-only", str(args.output / "client.o")], check=True)
