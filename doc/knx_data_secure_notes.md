# KNX Secure implementation notes

The current branch implements Data Secure Auth/AuthConf, full-address key
lookup, bounded parsing, randomized sync exchanges, authenticated replay state,
durable outgoing reservations and per-device runtime FDSK provisioning. Secure
tool management does not need the physical programming switch; anonymous cEMI
v1 remains anonymous even inside an authenticated IP session. Plain group objects
remain usable in the same Secure-capable application, according to ETS policy.

Platform integrations must provide `readFactoryDeviceKey`, cryptographic
`fillRandom`, and durable `readSecurityState`/`writeSecurityState` hooks.
Defaults fail closed. ESP-IDF uses manufacturing NVS, early hardware entropy,
CTR-DRBG, SHA256 and X25519; host tests use the OpenSSL backend. No common FDSK
is compiled into the library. Do not erase or roll back journals while reusing
keys, including on factory reset. Shared/default device serials are unsuitable
for production; IP Secure refuses the old demonstration serial.

IP Secure is integrated in the IP data link/tunnel server, including UDP/TCP
sessions, discovery, tunnel ACLs and durable multicast routing. It does not
advertise Secure local Device Management v2: local Secure transport APDUs are
rejected until the normative nonce/direction mapping is verified. Proxy group
translation and local temporary leases are integrated in the coupler routing
path, but the normative AN192 provisioning/temporary commands remain missing;
see [Secure Proxy qualification boundary](secure_proxy.md).

LTE/zone-addressing and the complete P2P role model are not implemented.
Historical PID_ZONE_KEY_TABLE/PID_ROLE_TABLE placeholders do not constitute
support. P2P key lookup and Tool authentication must not be confused with those
profiles. No complete KNX Secure or certification claim is made.

Current evidence is the host runtime suites (`test/CMakeLists.txt`), independent
vectors (`test/secure_vectors.py`), source contracts and native ESP-IDF syntax
checks (`test/espidf_secure_syntax.ps1`). They do not establish interoperability
with ETS5/ETS6 or a physical bus. The old AN158-based note asserting tested ETS
setup is not evidence for this rewritten implementation.

The RoomUnit integration uses one application6, KNX XML20, targeting ETS5.7+ and
ETS6. It advertises only the TP device's Data Secure capacity, not Proxy or IP
capabilities. A signed product database, XSD validation, actual Secure/plain
downloads and hardware qualification are still required.

References: [KNX Data Secure](https://support.knx.org/hc/en-us/articles/360012689639-KNX-Data-Secure),
[XKNX current Data Secure primitives](https://github.com/XKNX/xknx/blob/main/xknx/secure/data_secure_asdu.py),
[Calimero KNXnet/IP Secure](https://github.com/calimero-project/calimero-core/blob/master/src/io/calimero/knxnetip/SecureConnection.java).
