# C++ licensed export example

This console app opens an installation, asks for a licence key only when there
is no activation, and checks the `export` feature before protected work.

Install the prerequisites listed in the [C++ SDK guide](../../sdk/cpp/README.md),
set the public app key from your dashboard's **Integration** page, and run from
the repository root:

```sh
export ORBIT_APP_KEY='orbit_app_test_…'
cmake -S examples/cpp -B build/cpp -DBUILD_TESTING=OFF
cmake --build build/cpp
./build/cpp/orbit-cpp-licensed-export
```

The policy must include `export`. Launch again to reuse the saved activation.

For a policy with an `exports` usage limit, pass `--metered-export` and a stable
job ID, such as `export_job_000001`. The example reserves one unit before
printing a report. Reuse that job ID after an uncertain reply; a new ID is a new
debit.
