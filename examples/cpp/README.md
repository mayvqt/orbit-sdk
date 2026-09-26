# C++ licensing example

This example reads the public `ORBIT_APP_KEY`, opens an installation, asks for a
licence key only when there is no access, and checks the typed `export`
entitlement before protected work.

Build it from the repository root using the installed C++ prerequisites listed
in the [SDK README](../../sdk/cpp/README.md):

```sh
cmake -S examples/cpp -B build/cpp -DBUILD_TESTING=OFF
cmake --build build/cpp
./build/cpp/orbit-cpp-licensed-export --smoke
```

Run against your application by setting `ORBIT_APP_KEY` from Orbit's
**Integration** page (begin with Test):

```sh
export ORBIT_APP_KEY='orbit_app_test_…'
./build/cpp/orbit-cpp-licensed-export
```

The optional `--smoke` mode opens a temporary installation and makes no network
request.
