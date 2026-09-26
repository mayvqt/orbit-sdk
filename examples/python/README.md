# Python quickstart

Install the v0.2.0 package from the source release:

```sh
python -m pip install https://github.com/mayvqt/orbit-sdk/releases/download/v0.2.0/orbit_sdk-0.2.0-py3-none-any.whl
```

For source development from the repository root, install with
`python -m pip install ./sdk/python`, or set `PYTHONPATH=sdk/python` to use the
checkout directly. Python 3.12 or newer is required. The Python client uses
native Python logic and the `cryptography` package; no Rust build is needed.

Set the public integration values and an installation ID that the host
application saves between runs:

```sh
export ORBIT_API_ORIGIN='https://orbit.example'
export ORBIT_APPLICATION_ID='application_id'
export ORBIT_ENVIRONMENT_ID='environment_id'
export ORBIT_ISSUER='https://issuer.example'
export ORBIT_INSTALLATION_ID='persisted_installation_id'
export ORBIT_OPERATION_ID='stable_activation_operation_id'
```

For key activation, set `ORBIT_MODE=key` and enter the key at the hidden
prompt. For account activation, set `ORBIT_MODE=account`, optionally set
`ORBIT_USERNAME`, then sign in and select an owned licence at the prompts. Keep
the operation ID stable when retrying the same mutation after an uncertain
result.

Run the example with Python 3.12 or newer:

```sh
python examples/python/quickstart.py
```
