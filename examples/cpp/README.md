# C++ licensing example

Open an installation, activate it on first use, and check `export` access.
Normal restarts reuse the stored credential without asking for a key.

Install the [C++ SDK prerequisites](../../sdk/cpp/README.md), then build:

```sh
cmake -S examples/cpp -B build/cpp -DBUILD_TESTING=OFF
cmake --build build/cpp
./build/cpp/orbit-cpp-licensed-export --smoke
```

Run with the public values from Orbit's **Integration** page:

```sh
./build/cpp/orbit-cpp-licensed-export API_ORIGIN APP_ID ENV_ID ISSUER [STATE_DIRECTORY]
```

The optional state directory must be an absolute dedicated path; use a persistent
volume for containers. The example prompts for the key through stdin only when
access is unavailable. `--smoke` uses a temporary private installation and makes
no network request.
