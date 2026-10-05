# Secure Proxy routing API and qualification boundary

With `USE_DATASECURE`, `BauSystemBCoupler` connects a Secure Proxy to the actual
network routing path used by the IP/TP and TP/RF couplers. The normal direction
filter and hop-count check still apply before translation. Group Value Read,
Write, and Response can cross a configured plaintext/AuthConf boundary. The
proxy originates translated frames with its own individual address, uses the
Data Secure outgoing sequence reservation, and authenticates incoming frames
before committing sender replay state. Invalid MACs, unknown secure senders,
replays, unsupported services, incorrect security modes, disabled directions,
and oversized APDUs are dropped. Unconfigured group addresses retain the normal
router behavior; they are not automatically decrypted or converted.

Trusted product code can configure up to 50 `SecureProxyRule` entries through
`BauSystemBCoupler::configureSecureProxy`. Each entry defines an exact group
address, which interface carries AuthConf, allowed routing directions, and its
AES-128 group key. The `SecureProxyRule` fields are C++ API fields and **are not
an AN192 wire encoding**. This local configuration is volatile; the product must
reapply it from its authenticated provisioning storage after a reboot. Reset
clears these rules and their temporary routing leases.

When a proxy boundary is configured, cross-interface unicast and broadcast
routing fails closed. Trusted product code can grant a lease using
`allowTemporaryRoute(sourceIA, destination, sourceInterface, durationMs)`. Leases
match the exact source, destination, and direction; destination zero denotes
broadcast. They expire after at most 60 seconds, do not survive reboot or a
configuration change, and never bypass existing router filtering or hop-count
rules. These local APIs do not implement the normative AN192 temporary-filter
management commands.

The Router Object stores standard PID81 (`PDT_GENERIC_19`) records and persists
them through the existing Interface Object property save/restore mechanism.
Property reads and writes require authenticated confidential tool access.
`securityProxyDecoder` installs a trusted decoder mapping each 19-byte record
to an explicit rule. A populated table without a decoder, a table that is not
loaded, an unsupported record, conflicting duplicate settings, or an invalid
rule blocks cross-interface forwarding. Multiple Router Objects can contribute
rules, but matching group addresses must agree on keys and settings.
Factory reset writes the complete PID81 capacity as zero records and unloads
the Router Object so older serialized key bytes are overwritten on the reset
memory commit. A new authenticated configuration must replace this table before
the proxy can route again; restart and individual-address reset retain it.

The public Calimero property catalog establishes PID81's number and size, but
does not define its settings bit layout. It identifies PID82 as permanent
broadcast routing configuration; temporary routing uses Function Properties
PID83 (point-to-point) and PID84 (broadcast). Their command payloads and state
formats are not defined by that catalog. KNX Association's public overview
confirms group-only translation and temporary unicast/(system) broadcast
routing between specific individual addresses, but does not publish the bytes
of those operations. AN192 and the associated ETS download, capability, and
temporary-filter commands were not available for verification after checking
the KNX public material, manufacturer documentation, and public Calimero source.
The library therefore does not ship a guessed decoder or advertise qualified
ETS Secure Proxy support. A qualified AN192 decoder, the normative management
commands, ETS product metadata, and interoperable ETS/bus tests remain necessary
before claiming complete standard Secure Proxy support.

The separate cEMI local transport parser handles the published Individual and
Connected envelope formats and keeps plaintext management anonymous. It does
not enable Secure Device Management v2: secure local APDUs are rejected while
the normative nonce/direction mapping and tool-key-rotation response behavior
remain unverified. No Device Management v2 capability is advertised. cEMI
M_FuncProp commands return AccessDenied; state reads use the same public-read
policy as other anonymous property reads. This boundary does not affect
authenticated Tool AuthConf management received via the KNX bus transport.

Reference: [KNX Association Secure Proxy overview](https://www.knx.org/news/knx-security-proxy-what-it-good),
[Calimero Router Object property catalog](https://github.com/calimero-project/calimero-core/blob/master/resources/properties.xml).
