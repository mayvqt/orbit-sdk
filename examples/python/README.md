# Python quickstart

Requires Python 3.12 or newer. From the repository root, install the SDK into
your virtual environment and set the app key from Orbit's **Integration** page:

```sh
python -m pip install ./sdk/python
export ORBIT_APP_KEY='orbit_app_test_…'
python examples/python/quickstart.py
```

The quickstart reuses existing access and asks for a licence key only when the
installation has no activation. An outage is reported without prompting. Set
`ORBIT_STATE_PATH` to use a dedicated absolute state directory.

## Customer accounts

The username and password belong to your app's customer account, not an Orbit
dashboard account:

```sh
ORBIT_MODE=account ORBIT_USERNAME='alice' python examples/python/quickstart.py
```

The example prompts for the password without echoing it, lists the customer's
licences and activates the one you choose.

## Updates, usage and resources

After activation, discover and verify an update for installed release number
`1`, saving it to an explicit destination that must not exist yet:

```sh
python examples/python/online_operations.py 1 ./chosen-update.bin
```

The file is never executed. [`online_operations.py`](online_operations.py) also
shows reserving `exports` usage before a report and tracking `projects`
allocations; configure those limits on the policy first.

The [seller backend example](seller-downloads/README.md) verifies Orbit
download tickets before returning an expiring URL from private storage.
