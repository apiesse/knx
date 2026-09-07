# Host hardening checks

The production sources depend on an embedded `Platform`, a complete BAU object
graph, and target-specific transport implementations. OpenKNX currently ships
no native-host fixture for that graph. In addition, the Windows ESP-IDF toolchain
available in the firmware workspace has a compiler but no native Windows linker.

The test directory therefore uses two complementary checks:

- CMake object targets compile the actual policy, router, RF-medium, cEMI,
  KNXnet/IP tunnel and Core-v2 discovery parser, IP-parameter reset, and USB tunnel sources.
  Static assertions validate all combinations of the default management policy.
- `hardening_source_contract_test.py` executes source-level contracts for the
  security-sensitive integration points that cannot be linked here. Its scanner
  removes comments and quoted strings and extracts balanced C++ function bodies,
  so a comment or an unrelated function cannot accidentally satisfy a check.

Run the executable contracts directly with:

```text
python test/hardening_source_contract_test.py
```

With a native C++ toolchain, configure and build the object checks, then run
CTest:

```text
cmake -S test -B test/build -G Ninja
cmake --build test/build
ctest --test-dir test/build --output-on-failure
```

The object checks use a minimal declaration-only TPUART interface stub because
the selected implementation units only retain a pointer to that interface. No
TPUART behavior is duplicated or exercised by these checks; the firmware build
remains the integration test for the real dependency.

A future full behavioral unit test should introduce a supported in-memory
`Platform` fixture in upstream OpenKNX; duplicating the routing/reset algorithms
inside a test would not provide meaningful regression coverage.
