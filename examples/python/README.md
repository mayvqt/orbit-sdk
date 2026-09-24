# Python quickstart

This example supports either licence-key activation or customer-account
activation. It prompts for keys and passwords, reads public IDs from the
environment, and prints only access metadata.

From the SDK kit root, build the FFI on the target OS:

```sh
cargo build --release --manifest-path sdk/ffi/Cargo.toml
```

Set the public integration values and an installation ID that the host
application has saved between runs:

```sh
export ORBIT_API_ORIGIN='https://orbit.example'
export ORBIT_APPLICATION_ID='application_id'
export ORBIT_ENVIRONMENT_ID='environment_id'
export ORBIT_ISSUER='https://issuer.example'
export ORBIT_INSTALLATION_ID='persisted_installation_id'
export ORBIT_FFI_LIBRARY="$PWD/target/release/liborbit_sdk_ffi.so"
```

For key activation, set `ORBIT_MODE=key` and `ORBIT_OPERATION_ID`, then enter
the key at the hidden prompt. For account activation, set `ORBIT_MODE=account`
and `ORBIT_OPERATION_ID`, then sign in and select an owned licence at the
prompts. Keep that operation ID stable when retrying the same mutation after
an uncertain result. On Windows, use the built
`target/release/orbit_sdk_ffi.dll` path instead.

Run with Python 3.12 or newer and no third-party modules:

```sh
python examples/python/quickstart.py
```
