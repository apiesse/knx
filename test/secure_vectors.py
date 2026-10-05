"""Independent wire-format vectors using cryptography/OpenSSL, not tiny-AES.

IP layouts cross-checked against Calimero SecureConnection.java
(GPL-2.0-or-later, B. Malinowsky). Data Auth-only follows EN50090-3-4
and current XKNX, not the earlier draft Calimero Auth-only algorithm.
Only deliberately public test keys appear here; never use them on a bus.
Run with Python + cryptography to regenerate the fixed C++ known answers.
"""
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes(range(16))


def encrypt(mode, data):
    cipher = Cipher(algorithms.AES(KEY), mode).encryptor()
    return cipher.update(data) + cipher.finalize()


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def padded(data):
    return data + bytes((-len(data)) % 16)


def cbc(data):
    return encrypt(modes.CBC(bytes(16)), padded(data))


def ip_mac(nonce, associated, payload):
    return cbc(nonce + len(payload).to_bytes(2, "big")
               + len(associated).to_bytes(2, "big") + associated + payload)[-16:]


def ip_crypt(nonce, payload, mac):
    stream = encrypt(modes.CTR(nonce + b"\xff\x00"), bytes(16 + len(payload)))
    return xor(payload, stream[16:]), xor(mac, stream[:16])


def ip_wrapper():
    inner = bytes.fromhex("061002070010010008010a0000010e57")
    header = bytes.fromhex("06100950") + (len(inner) + 38).to_bytes(2, "big") + b"\x12\x34"
    nonce = bytes.fromhex("0102030405061122334455660000")
    payload, mac = ip_crypt(nonce, inner, ip_mac(nonce, header, inner))
    return (header + nonce + payload + mac).hex()


def ip_timer():
    header = bytes.fromhex("061009550024")
    nonce = bytes.fromhex("0102030405061122334455667788")
    _, mac = ip_crypt(nonce, b"", ip_mac(nonce, header, b""))
    return (header + nonce + mac).hex()


def ip_auth():
    associated = bytes.fromhex("0610095200381234") + bytes(range(32))
    mac = cbc(bytes(16) + len(associated).to_bytes(2, "big") + associated)[-16:]
    return xor(mac, encrypt(modes.ECB(), bytes(14) + b"\xff\x00")).hex()


def data_secure(conf, payload=bytes.fromhex("0080ab")):
    sequence = bytes.fromhex("000000000001")
    addresses = bytes.fromhex("11012345")
    b0 = sequence + addresses + bytes.fromhex("008003f100") + bytes([len(payload) if conf else 0])
    ctr = sequence + addresses + bytes.fromhex("000000000100")
    scf = bytes([0x10 if conf else 0])
    prefix = bytes.fromhex("03f1") + scf + sequence
    if conf:
        mac = cbc(b0 + b"\x00\x01" + scf + payload)[-16:-12]
        encoded = encrypt(modes.CTR(ctr), mac + payload)
        return (prefix + encoded[4:] + encoded[:4]).hex()
    # EN50090-3-4 Auth-only: P empty, A=SCF+inner APDU, final CBC tag,
    # no CTR. Current XKNX is an independent matching implementation.
    mac = cbc(b0 + (len(payload) + 1).to_bytes(2, "big") + scf + payload)[-16:-12]
    return (prefix + payload + mac).hex()


if __name__ == "__main__":
    print(json.dumps({"ip_wrapper": ip_wrapper(), "ip_timer": ip_timer(),
                      "ip_auth": ip_auth(), "data_authconf": data_secure(True),
                      "data_auth": data_secure(False),
                      "data_auth_long": data_secure(False, b"\x00\x80" + bytes(range(16)))}, indent=2))
