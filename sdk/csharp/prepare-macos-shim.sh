#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output=${1:?usage: prepare-macos-shim.sh OUTPUT_DYLIB}
mkdir -p "$(dirname -- "$output")"
xcrun --sdk macosx clang -dynamiclib -std=c11 -Wall -Wextra -Werror \
    -arch x86_64 -arch arm64 -mmacosx-version-min=10.13 \
    "$script_dir/Orbit.Sdk/Orbit.MacOSShim.c" -o "$output"

architectures=$(xcrun --sdk macosx lipo -archs "$output")
case " $architectures " in
    *" x86_64 "*" arm64 "*|*" arm64 "*" x86_64 "*) ;;
    *) echo "macOS shim must contain x86_64 and arm64 slices; found: $architectures" >&2; exit 1 ;;
esac
