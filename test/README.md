# Host hardening checks

The production sources depend on an embedded `Platform`, a complete BAU object
graph, and target-specific transport implementations. `behavioral_test.cpp`
provides an in-memory Platform and data link while exercising the real BAU,
group tables and application/transport layers. It covers memory, management
responses, transport revisions and the Read/Transmit GO flags, including
diagnostics that must remain unknown until their first local update. It also
round-trips DPT 20 one-byte enumerations through the real codec and GroupObject
telegram path, including HVAC profiles/machine modes and malformed inputs.
The ETS association-table description request is replayed through the real
application layer, including capacities above the 12-bit response limit in
both standard and extended descriptions.

The directory also uses two complementary checks:

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

With a native C++ toolchain, configure and build the checks, then run
CTest:

```text
cmake -S test -B test/build -G Ninja
cmake --build test/build
ctest --test-dir test/build --output-on-failure
```

On macOS, the host stack needs the system byte-order declarations explicitly:

```text
cmake -S test -B test/build -DCMAKE_CXX_FLAGS="-include arpa/inet.h" -DENABLE_SANITIZERS=ON
cmake --build test/build --target behavioral_test
ctest --test-dir test/build -R behavioral_test --output-on-failure
```

The object checks use a minimal declaration-only TPUART interface stub because
the selected implementation units only retain a pointer to that interface. No
TPUART behavior is duplicated or exercised by these checks; the firmware build
remains the integration test for the real dependency.

The in-memory data link does not emulate electrical TP-UART behavior or an ETS
download. Those remain integration checks on the actual device. Behavioral
tests call the production stack; they do not duplicate routing/reset algorithms.
