# Shared Rust FFI bridge

The C ABI in this crate connects the Rust SDK to the C++ and Python SDKs; it
is not a separate client API. Build a `staticlib` for C++ or a `cdylib` for
Python with the target platform's Rust toolchain, then follow that language's
setup guide.

Public declarations are in [orbit_ffi.h](../cpp/include/orbit_ffi.h). Keep the
bridge and Rust core at the same revision. Across languages, pass FFI pointer
ownership only through the documented free functions.
