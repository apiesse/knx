/*
 * KNXnet/IP Secure wire-format implementation for OpenKNX.
 * Protocol derivation and interoperability reference: Calimero SecureConnection,
 * SecureSessions and SecureRouting, Copyright (c) 2018-2025 B. Malinowsky,
 * https://github.com/calimero-project/calimero-core and calimero-server.
 * This implementation is distributed under GPL-3.0-or-later, consistently with
 * OpenKNX and the reference's GPL-2.0-or-later license.
 */
#include "ip_secure.h"
#if defined(USE_IP) && defined(USE_IPSECURE)
#include "bits.h"
extern "C" {
#include "aes.h"
}
#include <cstring>

namespace
{
void header(uint8_t* packet, uint16_t service, uint16_t length)
{
    packet[0] = 6; packet[1] = 0x10;
    pushWord(service, packet + 2); pushWord(length, packet + 4);
}
void securityInfo(const uint8_t* nonce, uint16_t length, uint8_t result[16])
{
    memcpy(result, nonce, 14); pushWord(length, result + 14);
}
void macBlock(AES_ctx& aes, uint8_t state[16], const uint8_t input[16])
{
    for (unsigned i = 0; i < 16; ++i) state[i] ^= input[i];
    AES_ECB_encrypt(&aes, state);
}
// Streaming CBC-MAC with explicit zero padding; associated data follows B0.
void mac(const uint8_t key[16], const uint8_t b0[16], const uint8_t* associated,
         uint16_t associatedLength, const uint8_t* payload, uint16_t payloadLength, uint8_t result[16])
{
    AES_ctx aes; AES_init_ctx(&aes, key);
    uint8_t state[16] = {}, block[16] = {};
    macBlock(aes, state, b0);
    const uint32_t total = 2U + associatedLength + payloadLength;
    for (uint32_t start = 0; start < total; start += 16)
    {
        memset(block, 0, sizeof(block));
        for (unsigned i = 0; i < 16 && start + i < total; ++i)
        {
            const uint32_t offset = start + i;
            if (offset == 0) block[i] = associatedLength >> 8;
            else if (offset == 1) block[i] = associatedLength & 0xff;
            else if (offset < 2U + associatedLength) block[i] = associated[offset - 2];
            else block[i] = payload[offset - 2 - associatedLength];
        }
        macBlock(aes, state, block);
    }
    memcpy(result, state, 16);
    KnxIpSecure::erase(&aes, sizeof(aes)); KnxIpSecure::erase(state, 16); KnxIpSecure::erase(block, 16);
}
void crypt(const uint8_t key[16], const uint8_t nonce[14], uint8_t* payload, uint16_t length, uint8_t tag[16])
{
    AES_ctx aes; AES_init_ctx(&aes, key);
    uint8_t counter[16], stream[16]; securityInfo(nonce, 0xff00, counter);
    memcpy(stream, counter, 16); AES_ECB_encrypt(&aes, stream);
    for (unsigned i = 0; i < 16; ++i) tag[i] ^= stream[i];
    for (uint16_t offset = 0; offset < length; offset += 16)
    {
        ++counter[15]; memcpy(stream, counter, 16); AES_ECB_encrypt(&aes, stream);
        for (unsigned i = 0; i < 16 && offset + i < length; ++i) payload[offset + i] ^= stream[i];
    }
    KnxIpSecure::erase(&aes, sizeof(aes)); KnxIpSecure::erase(stream, 16);
}
bool configuredKey(IpParameterObject& parameters, PropertyID id, uint16_t index, uint8_t output[16])
{
    memset(output, 0, 16);
    uint8_t count = 1; parameters.readProperty(id, index, count, output);
    const uint8_t zero[16] = {};
    return count == 1 && !KnxIpSecure::equal(output, zero, sizeof(zero));
}
void credentialFingerprint(const uint8_t key[16], uint8_t output[16])
{
    AES_ctx aes; AES_init_ctx(&aes, key); memset(output, 0, 16); AES_ECB_encrypt(&aes, output);
    KnxIpSecure::erase(&aes, sizeof(aes));
}
}

namespace KnxIpSecure
{
bool validFrame(const uint8_t* packet, uint16_t length)
{
    return packet && length >= 6 && packet[0] == 6 && packet[1] == 0x10 && getWord(packet + 4) == length;
}
uint64_t read48(const uint8_t* bytes)
{
    uint64_t value = 0; for (unsigned i = 0; i < 6; ++i) value = (value << 8) | bytes[i]; return value;
}
void write48(uint64_t value, uint8_t* bytes)
{
    for (int i = 5; i >= 0; --i) { bytes[i] = value & 0xff; value >>= 8; }
}
void erase(void* memory, size_t length)
{
    volatile uint8_t* bytes = static_cast<volatile uint8_t*>(memory);
    while (length--) *bytes++ = 0;
}
bool equal(const uint8_t* a, const uint8_t* b, size_t length)
{
    uint8_t difference = 0; for (size_t i = 0; i < length; ++i) difference |= a[i] ^ b[i]; return difference == 0;
}
bool wrap(const uint8_t key[16], uint16_t session, uint64_t sequence, const uint8_t serial[6], uint16_t tag,
          const uint8_t* inner, uint16_t innerLength, uint8_t* output, uint16_t capacity, uint16_t& outputLength)
{
    outputLength = 0;
    if (!key || !serial || !output || sequence > MaxSequence || !validFrame(inner, innerLength) ||
        innerLength > 4080 || uint32_t(innerLength) + Overhead > capacity) return false;
    const uint16_t size = innerLength + Overhead;
    // Copy first permits caller's inner buffer to overlap the output buffer.
    memmove(output + 22, inner, innerLength);
    header(output, Wrapper, size); pushWord(session, output + 6);
    write48(sequence, output + 8); memcpy(output + 14, serial, 6); pushWord(tag, output + 20);
    uint8_t b0[16], tagBytes[16]; securityInfo(output + 8, innerLength, b0);
    mac(key, b0, output, 8, output + 22, innerLength, tagBytes);
    crypt(key, output + 8, output + 22, innerLength, tagBytes);
    memcpy(output + 22 + innerLength, tagBytes, 16);
    erase(tagBytes, 16); outputLength = size; return true;
}
bool unwrap(const uint8_t key[16], const uint8_t* packet, uint16_t length, uint16_t expectedSession,
            uint8_t* inner, uint16_t capacity, uint16_t& innerLength)
{
    innerLength = 0;
    if (!key || !inner || !validFrame(packet, length) || getWord(packet + 2) != Wrapper ||
        length < 44 || length > KNX_IPSECURE_MAX_FRAME || getWord(packet + 6) != expectedSession) return false;
    const uint16_t size = length - Overhead;
    if (size > capacity || size > 4080) return false;
    uint8_t plaintext[KNX_IPSECURE_MAX_FRAME], received[16], calculated[16], b0[16];
    memcpy(plaintext, packet + 22, size); memcpy(received, packet + 22 + size, 16);
    crypt(key, packet + 8, plaintext, size, received);
    securityInfo(packet + 8, size, b0); mac(key, b0, packet, 8, plaintext, size, calculated);
    const bool valid = equal(received, calculated, 16) && validFrame(plaintext, size) &&
                       (getWord(plaintext + 2) < Wrapper || getWord(plaintext + 2) > TimerNotify ||
                        getWord(plaintext + 2) == SessionAuthenticate || getWord(plaintext + 2) == SessionStatus);
    if (valid) { memmove(inner, plaintext, size); innerLength = size; }
    erase(plaintext, sizeof(plaintext)); erase(received, 16); erase(calculated, 16);
    return valid;
}
void authenticationMac(const uint8_t key[16], const uint8_t packetHeader[8], const uint8_t xorPublicKeys[32], uint8_t result[16])
{
    uint8_t associated[40], zero[16] = {}, nonce[14] = {};
    memcpy(associated, packetHeader, 8); memcpy(associated + 8, xorPublicKeys, 32);
    mac(key, zero, associated, sizeof(associated), nullptr, 0, result);
    crypt(key, nonce, nullptr, 0, result); erase(associated, sizeof(associated));
}
bool timerNotify(const uint8_t key[16], uint64_t timer, const uint8_t serial[6], uint16_t tag, uint8_t packet[36])
{
    if (!key || !serial || !packet || timer > MaxSequence) return false;
    header(packet, TimerNotify, 36); write48(timer, packet + 6); memcpy(packet + 12, serial, 6); pushWord(tag, packet + 18);
    uint8_t b0[16], tagBytes[16]; securityInfo(packet + 6, 0, b0);
    mac(key, b0, packet, 6, nullptr, 0, tagBytes); crypt(key, packet + 6, nullptr, 0, tagBytes);
    memcpy(packet + 20, tagBytes, 16); erase(tagBytes, 16); return true;
}
bool verifyTimerNotify(const uint8_t key[16], const uint8_t* packet, uint16_t length)
{
    if (!key || !validFrame(packet, length) || length != 36 || getWord(packet + 2) != TimerNotify) return false;
    uint8_t expected[36]; timerNotify(key, read48(packet + 6), packet + 12, getWord(packet + 18), expected);
    const bool valid = equal(expected + 20, packet + 20, 16); erase(expected, sizeof(expected)); return valid;
}
}

IpSecureSessions::IpSecureSessions(Platform& platform, IpParameterObject& parameters, IpSecureSessionHandler& handler)
    : _platform(platform), _parameters(parameters), _handler(handler)
{ _parameters.securitySerialNumber(_serial); }
IpSecureSessions::~IpSecureSessions() { enabled(false); }
IpSecureSessions::Session* IpSecureSessions::find(uint16_t id)
{ for (auto& session : _sessions) if (id && session.id == id) return &session; return nullptr; }
const IpSecureSessions::Session* IpSecureSessions::find(uint16_t id) const
{ for (const auto& session : _sessions) if (id && session.id == id) return &session; return nullptr; }
bool IpSecureSessions::authenticated(uint16_t id) const { const auto* s = find(id); return s && s->user != 0; }
uint16_t IpSecureSessions::user(uint16_t id) const { const auto* s = find(id); return s ? s->user : 0; }
bool IpSecureSessions::isTcp(uint16_t id) const { const auto* s = find(id); return s && s->tcp >= 0; }
bool IpSecureSessions::endpoint(uint16_t id, uint32_t address, uint16_t port) const
{ const auto* s = find(id); return s && s->address == address && s->port == port; }
void IpSecureSessions::enabled(bool value)
{
    if (!value)
    {
        for (auto& session : _sessions) if (session.id) close(session.id);
        for (auto& stream : _streams) if (stream.connection >= 0) closeStream(stream);
        if (_listener) _platform.closeSecureTcpListener();
        _listener = false;
    }
    _enabled = value;
}
bool IpSecureSessions::sendRaw(Session& session, uint8_t* packet, uint16_t length)
{
    return session.tcp >= 0 ? _platform.sendSecureTcp(session.tcp, packet, length) :
                            _platform.sendBytesUniCast(session.address, session.port, packet, length);
}
bool IpSecureSessions::send(uint16_t id, uint8_t* packet, uint16_t length)
{
    Session* session = find(id);
    if (!session || session->sendSequence > KnxIpSecure::MaxSequence) return false;
    if (!credentialsCurrent(*session)) { close(id); return false; }
    uint8_t wrapped[KNX_IPSECURE_MAX_FRAME]; uint16_t wrappedLength;
    if (!KnxIpSecure::wrap(session->key, id, session->sendSequence++, session->serial, 0, packet, length,
                           wrapped, sizeof(wrapped), wrappedLength)) return false;
    const bool success = sendRaw(*session, wrapped, wrappedLength); KnxIpSecure::erase(wrapped, sizeof(wrapped));
    if (!success && session->tcp >= 0) close(id); // A partial stream write is not retryable.
    return success;
}
void IpSecureSessions::status(Session& session, uint8_t value)
{ uint8_t packet[8] = {}; header(packet, KnxIpSecure::SessionStatus, sizeof(packet)); packet[6] = value; send(session.id, packet, sizeof(packet)); }
void IpSecureSessions::close(uint16_t id)
{
    Session* session = find(id); if (!session) return;
    const int connection = session->tcp;
    releaseSession(*session);
    if (connection >= 0)
    {
        for (auto& stream : _streams) if (stream.connection == connection) { closeStream(stream); return; }
        _platform.closeSecureTcp(connection);
    }
}
void IpSecureSessions::releaseSession(Session& session)
{
    _handler.secureSessionClosed(session.id); KnxIpSecure::erase(&session, sizeof(session));
    session = Session();
}
bool IpSecureSessions::credentialsCurrent(const Session& session)
{
    uint8_t key[16], fingerprint[16], serial[6];
    bool current = _parameters.securitySerialNumber(serial) && KnxIpSecure::equal(serial, session.serial, 6) &&
                   configuredKey(_parameters, PID_DEVICE_AUTHENTICATION, 1, key);
    if (current)
    {
        credentialFingerprint(key, fingerprint);
        current = KnxIpSecure::equal(fingerprint, session.deviceCredential, 16);
    }
    if (current && session.user)
    {
        current = configuredKey(_parameters, PID_USER_PASSWORD_HASHES, session.user, key);
        if (current)
        {
            credentialFingerprint(key, fingerprint);
            current = KnxIpSecure::equal(fingerprint, session.userCredential, 16);
        }
    }
    KnxIpSecure::erase(key, 16); KnxIpSecure::erase(fingerprint, 16);
    return current;
}
void IpSecureSessions::request(uint8_t* packet, uint16_t length, uint32_t address, uint16_t port, int tcp)
{
    if (!_parameters.securitySerialNumber(_serial)) return;
    if (length != 46 || packet[6] != 8 || packet[7] != (tcp >= 0 ? 2 : 1)) return;
    if (tcp >= 0 && (getInt(packet + 8) != 0 || getWord(packet + 12) != 0)) return;
    if (tcp < 0 && ((getInt(packet + 8) && getInt(packet + 8) != address) ||
                   (getWord(packet + 12) && getWord(packet + 12) != port))) return;
    uint8_t authKey[16]; if (!configuredKey(_parameters, PID_DEVICE_AUTHENTICATION, 1, authKey)) return;
    Session* slot = nullptr;
    for (auto& s : _sessions)
    {
        if (tcp >= 0 && s.id && s.tcp == tcp)
        { KnxIpSecure::erase(authKey, 16); return; } // One secure session per TCP connection.
        if (s.id && s.address == address && s.port == port && s.tcp == tcp && !s.user)
        { KnxIpSecure::erase(authKey, 16); return; }
        if (!s.id && !slot) slot = &s;
    }
    if (!slot)
    {
        Session rejected; rejected.address = address; rejected.port = port; rejected.tcp = tcp;
        uint8_t response[8] = {}; header(response, KnxIpSecure::SessionResponse, 8); sendRaw(rejected, response, 8);
        KnxIpSecure::erase(authKey, 16); return;
    }
    uint8_t privateKey[32] = {}, publicKey[32], shared[32], digest[32], base[32] = {9}, zero[32] = {};
    const bool crypto = _platform.fillRandom(privateKey, sizeof(privateKey)) &&
                        _platform.secureX25519(privateKey, base, publicKey) &&
                        _platform.secureX25519(privateKey, packet + 14, shared) &&
                        !KnxIpSecure::equal(shared, zero, 32) &&
                        _platform.secureSha256(shared, sizeof(shared), digest);
    if (!crypto)
    {
        KnxIpSecure::erase(privateKey, 32); KnxIpSecure::erase(shared, 32); KnxIpSecure::erase(authKey, 16);
        return;
    }
    do { ++_nextId; } while (!_nextId || find(_nextId));
    slot->id = _nextId; slot->address = address; slot->port = port; slot->tcp = tcp;
    slot->lastActivity = millis(); memcpy(slot->key, digest, 16);
    memcpy(slot->serial, _serial, sizeof(slot->serial));
    credentialFingerprint(authKey, slot->deviceCredential);
    for (unsigned i = 0; i < 32; ++i) slot->xorPublic[i] = publicKey[i] ^ packet[14 + i];
    uint8_t response[56] = {}; header(response, KnxIpSecure::SessionResponse, sizeof(response)); pushWord(slot->id, response + 6);
    memcpy(response + 8, publicKey, 32);
    KnxIpSecure::authenticationMac(authKey, response, slot->xorPublic, response + 40);
    if (!sendRaw(*slot, response, sizeof(response))) close(slot->id);
    KnxIpSecure::erase(authKey, 16); KnxIpSecure::erase(privateKey, 32); KnxIpSecure::erase(shared, 32); KnxIpSecure::erase(digest, 32);
}
bool IpSecureSessions::receive(uint8_t* packet, uint16_t length, uint32_t address, uint16_t port, int tcp)
{
    if (!_enabled || !KnxIpSecure::validFrame(packet, length)) return false;
    const uint16_t service = getWord(packet + 2);
    if (service == KnxIpSecure::SessionRequest) { request(packet, length, address, port, tcp); return true; }
    if (service != KnxIpSecure::Wrapper) return false;
    if (length < 44) return true;
    Session* session = find(getWord(packet + 6));
    if (!session || !endpoint(session->id, address, port) || session->tcp != tcp || getWord(packet + 20) != 0) return true;
    if (!credentialsCurrent(*session)) { close(session->id); return true; }
    const uint64_t sequence = KnxIpSecure::read48(packet + 8);
    if (session->received && sequence <= session->receiveSequence) return true;
    uint8_t inner[KNX_IPSECURE_MAX_FRAME]; uint16_t innerLength;
    if (!KnxIpSecure::unwrap(session->key, packet, length, session->id, inner, sizeof(inner), innerLength)) return true;
    session->receiveSequence = sequence; session->received = true; session->lastActivity = millis();
    const uint16_t innerService = getWord(inner + 2);
    if (innerService == KnxIpSecure::SessionAuthenticate)
    {
        bool success = false;
        if (!session->user && innerLength == 24)
        {
            const uint16_t userId = getWord(inner + 6); uint8_t userKey[16], expected[16];
            if (userId >= 1 && userId <= 127 && configuredKey(_parameters, PID_USER_PASSWORD_HASHES, userId, userKey))
            {
                KnxIpSecure::authenticationMac(userKey, inner, session->xorPublic, expected);
                success = KnxIpSecure::equal(expected, inner + 8, 16);
                if (success) { session->user = userId; credentialFingerprint(userKey, session->userCredential); }
            }
            KnxIpSecure::erase(userKey, 16); KnxIpSecure::erase(expected, 16);
        }
        status(*session, success ? 0 : 1);
        KnxIpSecure::erase(session->xorPublic, 32);
        if (!success) close(session->id);
    }
    else if (!session->user) { status(*session, 2); close(session->id); }
    else if (innerService == KnxIpSecure::SessionStatus)
    {
        if (innerLength != 8 || inner[7] != 0 || (inner[6] != 4 && inner[6] != 5)) close(session->id);
        else if (inner[6] == 5) { status(*session, 5); close(session->id); }
    }
    else _handler.secureIpFrame(inner, innerLength, address, port, session->id);
    KnxIpSecure::erase(inner, sizeof(inner)); return true;
}
void IpSecureSessions::closeStream(Stream& stream)
{
    for (auto& session : _sessions) if (session.id && session.tcp == stream.connection) releaseSession(session);
    _platform.closeSecureTcp(stream.connection); KnxIpSecure::erase(stream.data, sizeof(stream.data)); stream = Stream();
}
void IpSecureSessions::loop()
{
    if (!_enabled) return;
    if (!_listener) _listener = _platform.setupSecureTcp(KNXIP_MULTICAST_PORT);
    uint32_t address = 0; uint16_t port = 0;
    const int connection = _listener ? _platform.acceptSecureTcp(address, port) : -1;
    if (connection >= 0)
    {
        Stream* slot = nullptr; for (auto& stream : _streams) if (stream.connection < 0) { slot = &stream; break; }
        if (!slot) _platform.closeSecureTcp(connection);
        else { slot->connection = connection; slot->address = address; slot->port = port; slot->lastActivity = millis(); }
    }
    for (auto& stream : _streams)
    {
        if (stream.connection < 0) continue;
        if (millis() - stream.lastActivity >= 60000) { closeStream(stream); continue; }
        const int received = _platform.readSecureTcp(stream.connection, stream.data + stream.used, sizeof(stream.data) - stream.used);
        if (received < 0 || received > int(sizeof(stream.data) - stream.used)) { closeStream(stream); continue; }
        stream.used += received;
        while (stream.connection >= 0 && stream.used >= 6)
        {
            const uint16_t length = getWord(stream.data + 4);
            if (stream.data[0] != 6 || stream.data[1] != 0x10 || length < 6 || length > sizeof(stream.data)) { closeStream(stream); break; }
            if (stream.used < length) break;
            if (!receive(stream.data, length, stream.address, stream.port, stream.connection)) { closeStream(stream); break; }
            if (stream.connection < 0) break; // SESSION_STATUS close/revocation released the stream.
            // Only a cryptographically valid packet refreshes the session timeout;
            // stream lifetime is governed by its active session, or request deadline.
            for (const auto& session : _sessions) if (session.id && session.tcp == stream.connection) stream.lastActivity = session.lastActivity;
            stream.used -= length; memmove(stream.data, stream.data + length, stream.used);
        }
    }
    for (auto& session : _sessions)
    {
        if (!session.id) continue;
        if (!credentialsCurrent(session)) { close(session.id); continue; }
        const uint32_t timeout = session.user ? 60000 : 10000;
        if (millis() - session.lastActivity >= timeout) { status(session, 3); close(session.id); }
    }
}

IpSecureRouting::IpSecureRouting(Platform& platform, IpParameterObject& parameters)
    : _platform(platform), _parameters(parameters) { _parameters.securitySerialNumber(_serial); }
bool IpSecureRouting::required() const { return _parameters.secureServiceFamilies() & (1U << 5); }
void IpSecureRouting::enabled(bool value)
{
    _enabled = value; _configured = false; _synchronized = false;
    KnxIpSecure::erase(_key, sizeof(_key));
    for (auto& replay : _replay) replay = Replay();
}
bool IpSecureRouting::randomDelay(uint32_t low, uint32_t high, uint32_t& value)
{
    uint32_t entropy;
    if (high < low || !_platform.fillRandom(reinterpret_cast<uint8_t*>(&entropy), sizeof(entropy))) return false;
    value = low + entropy % (high - low + 1); return true;
}
bool IpSecureRouting::reserve(uint64_t timer)
{
    if (timer >= KnxIpSecure::MaxSequence - 60000) return false;
    if (timer < _reserved) return true;
    uint8_t record[36] = {'I','P','R','3'};
    AES_ctx aes; AES_init_ctx(&aes, _key); AES_ECB_encrypt(&aes, record + 4);
    KnxIpSecure::erase(&aes, sizeof(aes));
    const uint64_t limit = timer + 60000; KnxIpSecure::write48(limit, record + 20);
    pushInt(_multicast, record + 26);
    memcpy(record + 30, _serial, 6);
    if (!_platform.writeSecurityState(0x100000, record, sizeof(record))) return false;
    _reserved = limit; return true;
}
bool IpSecureRouting::configure()
{
    if (!_enabled || !required()) return false;
    uint8_t serial[6];
    if (!_parameters.securitySerialNumber(serial)) return false;
    uint8_t key[16];
    if (!configuredKey(_parameters, PID_BACKBONE_KEY, 1, key)) return false;
    const uint32_t multicast = _parameters.propertyValue<uint32_t>(PID_ROUTING_MULTICAST_ADDRESS);
    const uint16_t latency = _parameters.propertyValue<uint16_t>(PID_MULTICAST_LATENCY_TOLERANCE);
    const uint8_t fraction = _parameters.propertyValue<uint8_t>(PID_SYNC_LATENCY_FRACTION);
    if (_configured && KnxIpSecure::equal(key, _key, 16) && multicast == _multicast &&
        latency == _latency && fraction == _latencyFraction && KnxIpSecure::equal(serial, _serial, 6))
    { KnxIpSecure::erase(key, 16); return true; }
    memcpy(_key, key, 16); KnxIpSecure::erase(key, 16);
    memcpy(_serial, serial, 6);
    _configured = false; _synchronized = false; _keeper = false; _periodic = true; _reserved = 0; _timer = 0; _initialNotified = false;
    _multicast = multicast; _latency = latency; _latencyFraction = fraction;
    const uint8_t zeroSerial[6] = {};
    if ((multicast & 0xf0000000U) != 0xe0000000U || !_latency || _latency > 8000 || !fraction ||
        KnxIpSecure::equal(_serial, zeroSerial, sizeof(zeroSerial))) return false;
    _syncLatency = uint32_t(_latency) * fraction / 255U;
    if (!_syncLatency) _syncLatency = 1;
    uint32_t delay;
    if (!randomDelay(0, 10000, delay)) return false;
    uint8_t record[36], fingerprint[16] = {};
    AES_ctx aes; AES_init_ctx(&aes, _key); AES_ECB_encrypt(&aes, fingerprint); KnxIpSecure::erase(&aes, sizeof(aes));
    const int size = _platform.readSecurityState(0x100000, record, sizeof(record));
    if (size < 0 || (size != 0 && size != sizeof(record))) return false;
    bool sameKey = false;
    if (size)
    {
        if (memcmp(record, "IPR3", 4)) return false;
        sameKey = KnxIpSecure::equal(record + 4, fingerprint, 16);
        // A backbone key belongs to one multicast group. A direct group change
        // without rekeying is rejected, including after a restart.
        if (sameKey && (getInt(record + 26) != multicast || !KnxIpSecure::equal(record + 30, _serial, 6))) return false;
        if (sameKey) _timer = KnxIpSecure::read48(record + 20);
    }
    // ISO 22510 resets the timer to zero on a new backbone key. Reintroducing
    // an old key would consequently reuse nonces; retain a durable key-use
    // marker and reject old keys. Hash collisions fail closed, never alias.
    const uint32_t markerId = 0x80000000U | (getInt(fingerprint) & 0x7fffffffU);
    uint8_t marker[24] = {};
    const int markerSize = _platform.readSecurityState(markerId, marker, sizeof(marker));
    if (markerSize < 0 || (markerSize != 0 && markerSize != sizeof(marker))) return false;
    if (markerSize && (memcmp(marker, "IPK1", 4) || !KnxIpSecure::equal(marker + 4, fingerprint, 16) ||
                       marker[20] > 1 || marker[21] || marker[22] || marker[23])) return false;
    if (!sameKey && markerSize && marker[20] == 1) return false;
    if (!markerSize)
    {
        memcpy(marker, "IPK1", 4); memcpy(marker + 4, fingerprint, 16);
        // Pending marker permits retry when the following atomic write fails.
        if (!_platform.writeSecurityState(markerId, marker, sizeof(marker))) return false;
    }
    // A reservation is durable before a timer can be used in an outgoing nonce.
    if (!reserve(_timer)) return false;
    if (!marker[20])
    {
        marker[20] = 1;
        if (!_platform.writeSecurityState(markerId, marker, sizeof(marker))) return false;
    }
    _lastClock = _startClock = millis();
    _notifyAt = _lastClock + delay;
    for (auto& replay : _replay) replay = Replay();
    _configured = true; return true;
}
void IpSecureRouting::advance()
{
    const uint32_t now = millis(); _timer += uint32_t(now - _lastClock); _lastClock = now;
    if (_timer > KnxIpSecure::MaxSequence || !reserve(_timer)) _configured = false;
}
void IpSecureRouting::schedule(bool periodic)
{
    _periodic = periodic;
    const uint32_t low = periodic ? (_keeper ? 10000 : 10000 + 4U * _syncLatency) :
                                   (_keeper ? 100 : 100 + 2U * _syncLatency);
    const uint32_t high = low + (_keeper ? (periodic ? 3U : 1U) : 10U) * _syncLatency;
    uint32_t delay;
    if (!randomDelay(low, high, delay)) { _configured = false; return; }
    _notifyAt = millis() + delay;
}
bool IpSecureRouting::notify()
{
    uint8_t packet[36];
    if (_periodic)
    {
        uint32_t tag;
        if (!randomDelay(1, 65535, tag)) return false;
        _notifyTag = tag; memcpy(_notifySerial, _serial, 6);
    }
    if (!KnxIpSecure::timerNotify(_key, _timer, _notifySerial, _notifyTag, packet)) return false;
    const bool success = _platform.sendBytesMultiCast(packet, sizeof(packet));
    _initialNotified = true;
    _keeper = true; schedule(true); return success;
}
void IpSecureRouting::loop()
{
    if (!configure()) return;
    advance(); if (!_configured) return;
    if (!_synchronized && millis() - _startClock >= 2U * _latency + 100U + 12U * _syncLatency)
        _synchronized = true;
    if (int32_t(millis() - _notifyAt) >= 0) notify();
}
void IpSecureRouting::synchronize(uint64_t remote, const uint8_t serial[6], uint16_t tag, bool notification)
{
    if (remote > _timer)
    {
        if (!reserve(remote)) { _configured = false; return; }
        _timer = remote;
        if (notification) _keeper = false;
        if (notification && tag == _notifyTag && KnxIpSecure::equal(serial, _serial, 6)) _synchronized = true;
        schedule(true);
    }
    else if (_timer - remote <= _syncLatency)
    {
        if (notification && tag == _notifyTag && KnxIpSecure::equal(serial, _serial, 6)) _synchronized = true;
        if (notification) _keeper = false;
        schedule(true);
    }
    else if (_timer - remote >= _latency && _periodic)
    {
        memcpy(_notifySerial, serial, 6); _notifyTag = tag; schedule(false);
    }
}
bool IpSecureRouting::send(uint8_t* packet, uint16_t length)
{
    if (!configure()) return false;
    advance(); if (!_configured) return false;
    if (!_synchronized)
    {
        // Immediate transmission asks for an authentic group timer first.
        if (!_initialNotified) notify();
        return false;
    }
    if (_tagTimer != _timer) { _tagTimer = _timer; _tag = 0; }
    if (_tag > 0xffff)
    {
        // Even a caller bypassing the routing rate limit cannot wrap the tag
        // and reuse a nonce within one millisecond.
        if (_timer == KnxIpSecure::MaxSequence || !reserve(_timer + 1)) return false;
        _tagTimer = ++_timer; _tag = 0;
    }
    uint8_t wrapped[KNX_IPSECURE_MAX_FRAME]; uint16_t size;
    if (!KnxIpSecure::wrap(_key, 0, _timer, _serial, uint16_t(_tag++), packet, length, wrapped, sizeof(wrapped), size)) return false;
    const bool success = _platform.sendBytesMultiCast(wrapped, size); schedule(true); return success;
}
uint16_t IpSecureRouting::receive(uint8_t* packet, uint16_t length)
{
    if (!configure()) return 0;
    advance(); if (!_configured || !KnxIpSecure::validFrame(packet, length)) return 0;
    if (getWord(packet + 2) == KnxIpSecure::TimerNotify)
    {
        if (KnxIpSecure::verifyTimerNotify(_key, packet, length))
            synchronize(KnxIpSecure::read48(packet + 6), packet + 12, getWord(packet + 18), true);
        return 0;
    }
    uint8_t inner[KNX_IPSECURE_MAX_FRAME]; uint16_t size;
    if (!KnxIpSecure::unwrap(_key, packet, length, 0, inner, sizeof(inner), size)) return 0;
    const uint64_t timer = KnxIpSecure::read48(packet + 8); const uint16_t tag = getWord(packet + 20);
    synchronize(timer, packet + 14, tag, false);
    if (!_configured || !_synchronized || _timer - timer > _latency ||
        getWord(inner + 2) < 0x0530 || getWord(inner + 2) > 0x0533) return 0;
    // Duplicate suppression within the latency window; a full live cache fails
    // closed instead of evicting entries an attacker could immediately replay.
    Replay* free = nullptr;
    for (auto& replay : _replay)
    {
        if (replay.used && _timer >= replay.timer && _timer - replay.timer > _latency) replay.used = false;
        if (!replay.used) { if (!free) free = &replay; continue; }
        if (replay.timer == timer && replay.tag == tag && KnxIpSecure::equal(replay.serial, packet + 14, 6)) return 0;
    }
    if (!free) return 0;
    free->used = true; free->timer = timer; free->tag = tag; memcpy(free->serial, packet + 14, 6);
    memcpy(packet, inner, size); KnxIpSecure::erase(inner, sizeof(inner)); return size;
}
#endif
