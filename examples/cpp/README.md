# C++ licensing example

The example connects with the public origin, application ID, environment ID and
issuer from Orbit Integration. It prints the current snapshot, prompts for a
licence key, activates, and checks `export` access. The key is read from stdin
instead of a command-line argument.

Follow the [C++ SDK build and security notes](../../sdk/cpp/README.md). Run
`orbit-cpp-licensed-export --smoke` to exercise client creation and snapshot
handling without making a network request.
