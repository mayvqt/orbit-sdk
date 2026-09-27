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
parser.add_argument("--profile", choices=("connected", "services", "offline-compact", "offline-full"), default="connected")
args = parser.parse_args()
flags = []
sources = ["grant", "json", "prepare", "jwks", "client", "wire", "storage", "app_key"]
if args.profile != "connected":
    flags += ["-DORBIT_ENABLE_SERVICES=1"]
    sources += ["services_codec", "limits", "downloads", "extensions", "sessions"]
if args.profile.startswith("offline"):
    flags += ["-DORBIT_ENABLE_OFFLINE=1", "-DORBIT_OFFLINE_PROFILE_FILE_BYTES=" + ("4096" if args.profile.endswith("compact") else "16384")]
    sources += ["offline"]
root = Path(__file__).resolve().parents[1]
args.output.mkdir(parents=True, exist_ok=True)
objects = []
frames = {}
edges = {}
for name in sources:
    obj = args.output / f"orbit_{name}.o"
    subprocess.run(["clang", "--target=arm-none-eabi", "-mcpu=cortex-m0plus", "-mthumb",
                    "-std=c11", "-Os", "-ffreestanding", "-fno-builtin", "-fstack-usage",
                    "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra",
                    "-Wpedantic", "-Werror", *flags, f"-I{root / 'include'}", "-c",
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
if args.profile != "connected":
    edges.setdefault("orbit_client_fetch_keys", set()).add("receive_keys")
    edges.setdefault("orbit_service_exchange", set()).add("receive_service")
if args.profile.startswith("offline"):
    edges.setdefault("save", set()).add("orbit_extension_commit")
    edges.setdefault("orbit_extension_commit", set()).add("orbit_journal_commit")
    edges.setdefault("orbit_extension_load", set()).add("orbit_journal_load")

def peak(name, path=()):
    if name not in frames:
        return (0, ())
    count = path.count(name)
    if count >= (16 if name == "orbit_json_skip_value" else 1):
        return (0, ())
    following = max((peak(child, path + (name,)) for child in edges.get(name, ())),
                    default=(0, ()))
    return (frames[name] + following[0], (name,) + following[1])

for name in ("orbit_grant_verify", "orbit_jwks_import", "orbit_app_key_parse",
             "orbit_client_activate", "orbit_client_require_access",
             "orbit_client_deactivate", "orbit_client_import_offline_file", "orbit_client_import_offline_reader", "orbit_client_init_extended", "orbit_client_start_session", "orbit_client_consume", "orbit_client_check_for_updates", "orbit_download_stream"):
    if name not in frames:
        continue
    size, path = peak(name)
    print(f"Conservative portable stack {name}: {size} bytes; {' -> '.join(path)}")
print("Unresolved target runtime (must be supplied by the actual board toolchain):")
subprocess.run(["llvm-nm", "--undefined-only", str(args.output / "client.o")], check=True)

layout = '#include "orbit_extensions.h"\nconst unsigned orbit_measure_state=sizeof(orbit_client_t);\nconst unsigned orbit_measure_extension=sizeof(orbit_client_extension_t);\n'
ir = subprocess.check_output(["clang", "--target=arm-none-eabi", "-mcpu=cortex-m0plus", "-mthumb", "-S", "-emit-llvm", "-x", "c", *flags, f"-I{root / 'include'}", "-o", "-", "-"], input=layout, text=True)
for name,value in re.findall(r'@(orbit_measure_\w+) = .*?constant i32 (\d+)',ir):
    print(f"M0+ {name}: {value} bytes")
