# Python quickstart

From the repository root, install the SDK into your application's virtual
environment:

```sh
python -m pip install ./sdk/python
```

Alternatively, set `PYTHONPATH=sdk/python` to use the checkout directly.
Python 3.12 or newer is required. The Python client uses
native Python logic and the `cryptography` package; no Rust build is needed.

Copy the app key from Orbit's **Integration** page and set one variable:

```sh
export ORBIT_APP_KEY='orbit_app_test_...'
```

Run the key activation example:

```sh
python examples/python/quickstart.py
```

The quickstart reuses valid online or offline access. It asks for a key only
when no usable activation exists; network outages are shown without prompting
for another key. The SDK keeps the secure retry ID and an input digest for an
activation with an uncertain result. It never stores the raw key.

The client uses the native machine identity by default when available. Set
`ORBIT_STATE_PATH` to an absolute private directory on persistent storage for
a service or container. If a container shares machine identity with its image,
open it with `machine_binding=False` in your application.

## Optional: customer accounts

The username and password belong to your app's customer account, not an Orbit
dashboard account. Sign-in does not grant access; customers still choose and
activate a licence.

```sh
export ORBIT_MODE=account
export ORBIT_USERNAME='alice'
python examples/python/quickstart.py
```

The example prompts for the password without echoing it, lists the customer's
owned licences and activates the selected licence. `ORBIT_MODE` defaults to
`key`.

## Seller-hosted downloads

The [seller backend example](seller-downloads/README.md) demonstrates verifying
Orbit download tickets before returning an expiring URL from the seller's
private S3-compatible storage. Ticket verification runs on the seller's backend,
separately from the installed application.
