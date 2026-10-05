#include "knx/security_interface_object.h"
#include "knx/bits.h"
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <map>
#include <vector>

uint32_t millis() { return 1; }
void delay(uint32_t) {}
void delayMicroseconds(unsigned int) {}
void pinMode(uint32_t, uint32_t) {}
void digitalWrite(uint32_t, uint32_t) {}
uint32_t digitalRead(uint32_t) { return 0; }
void attachInterrupt(uint32_t, voidFuncPtr, uint32_t) {}

// Models a separately durable journal.  Discarding the SecurityInterfaceObject
// models loss of all RAM without saving the delayed EEPROM image.
class JournalPlatform : public Platform
{
public:
    std::map<uint32_t, std::vector<uint8_t>> durable;
    bool commitSucceeds = true;
    bool readSucceeds = true;
    bool provisioned = true;
    unsigned commits = 0;
    void restart() override {}
    void fatalError() override { std::abort(); }
    bool readFactoryDeviceKey(uint8_t key[16]) override
    {
        for (unsigned index = 0; index < 16; ++index)
            key[index] = static_cast<uint8_t>(index + 1);
        return provisioned;
    }
    bool fillRandom(uint8_t* data, size_t length) override
    {
        if (!data || !length)
            return false;
        memset(data, 0xa5, length);
        return true;
    }
    int readSecurityState(uint32_t id, uint8_t* data, size_t capacity) override
    {
        if (!readSucceeds)
            return -1;
        auto record = durable.find(id);
        if (record == durable.end())
            return 0;
        if (record->second.size() > capacity)
            return -1;
        memcpy(data, record->second.data(), record->second.size());
        return static_cast<int>(record->second.size());
    }
    bool writeSecurityState(uint32_t id, const uint8_t* data, size_t length) override
    {
        if (!commitSucceeds)
            return false;
        durable[id] = std::vector<uint8_t>(data, data + length);
        ++commits;
        return true;
    }
};

class Fixture
{
public:
    SecurityInterfaceObject security;
    explicit Fixture(JournalPlatform& platform) { security.bindPlatform(platform); }
    void addSender(uint16_t sender, uint64_t sequence = 0)
    {
        uint8_t entry[8];
        pushWord(sender, entry);
        sixBytesFromUInt64(sequence, entry + 2);
        assert(security.property(PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE)->write(1, 1, entry) == 1);
    }
};

static void reservationsSurviveAbruptPowerLoss()
{
    JournalPlatform platform;
    uint64_t sequence = 0;
    {
        Fixture first(platform);
        assert(first.security.reserveOutgoingSequence(false, sequence) && sequence == 1);
        assert(first.security.reserveOutgoingSequence(false, sequence) && sequence == 2);
        assert(platform.commits == 1); // no whole EEPROM image per telegram
        assert(first.security.reserveOutgoingSequence(true, sequence) && sequence == 1);
        assert(platform.commits == 2); // independent tool domain
    }
    {
        Fixture restarted(platform);
        assert(restarted.security.nextSequenceNumber(false) == KNX_SECURE_SEQUENCE_RESERVATION + 1);
        assert(restarted.security.reserveOutgoingSequence(false, sequence));
        assert(sequence == KNX_SECURE_SEQUENCE_RESERVATION + 1);
        assert(restarted.security.nextSequenceNumber(true) == KNX_SECURE_SEQUENCE_RESERVATION + 1);
    }
}

static void failedCommitsNeverAuthorizeTraffic()
{
    JournalPlatform platform;
    Fixture fixture(platform);
    uint64_t sequence = 7;
    platform.commitSucceeds = false;
    assert(!fixture.security.reserveOutgoingSequence(false, sequence) && sequence == 0);
    assert(fixture.security.nextSequenceNumber(false) == 1);
    assert(!fixture.security.ensureOutgoingSequenceAtLeast(false, 10000));
    assert(fixture.security.nextSequenceNumber(false) == 1);
    assert(!fixture.security.acceptIncomingSequence(true, 0x1234, 11));
    assert(fixture.security.lastValidSequenceNumber(true, 0x1234) == 0);
    platform.commitSucceeds = true;
    assert(fixture.security.reserveOutgoingSequence(false, sequence) && sequence == 1);
    assert(fixture.security.acceptIncomingSequence(true, 0x1234, 11));
}

static void replayStateIsSeparatedAndDurable()
{
    JournalPlatform platform;
    {
        Fixture fixture(platform);
        fixture.addSender(0x1234, 20);
        assert(fixture.security.isKnownSender(0x1234));
        assert(!fixture.security.isKnownSender(0x4321));
        assert(!fixture.security.acceptIncomingSequence(false, 0x1234, 20));
        assert(fixture.security.acceptIncomingSequence(false, 0x1234, 21));
        assert(fixture.security.acceptIncomingSequence(true, 0x1234, 2));
        assert(!fixture.security.acceptIncomingSequence(false, 0x1234, 21));
        assert(!fixture.security.acceptIncomingSequence(true, 0x1234, 2));
        fixture.addSender(0x1234, 25); // ETS raises an already cached sender floor
        assert(!fixture.security.acceptIncomingSequence(false, 0x1234, 24));
        assert(fixture.security.acceptIncomingSequence(false, 0x1234, 26));
    }
    Fixture restarted(platform);
    restarted.addSender(0x1234); // old ETS image cannot roll replay protection back
    assert(restarted.security.lastValidSequenceNumber(false, 0x1234) == 26);
    assert(restarted.security.lastValidSequenceNumber(true, 0x1234) == 2);
    assert(!restarted.security.acceptIncomingSequence(false, 0x1234, 20));
    assert(restarted.security.acceptIncomingSequence(false, 0x1234, 27));
}

static void liveEtsSequenceFloorsAreMonotonicAndDurable()
{
    JournalPlatform platform;
    Fixture fixture(platform);
    uint64_t sequence = 0;
    assert(fixture.security.reserveOutgoingSequence(false, sequence) && sequence == 1);
    uint8_t configured[6];
    sixBytesFromUInt64(10000, configured);
    assert(fixture.security.property(PID_SEQUENCE_NUMBER_SENDING)->write(1, 1, configured) == 1);
    assert(fixture.security.nextSequenceNumber(false) == 10000);
    platform.commitSucceeds = false;
    assert(!fixture.security.reserveOutgoingSequence(false, sequence) && sequence == 0);
    assert(fixture.security.nextSequenceNumber(false) == 10000);
    std::vector<uint8_t> image(fixture.security.saveSize());
    fixture.security.save(image.data());
    assert(fixture.security.nextSequenceNumber(false) == 10000); // save must not discard ETS floor
    platform.commitSucceeds = true;
    Fixture restarted(platform);
    restarted.security.restore(image.data());
    assert(restarted.security.nextSequenceNumber(false) == 10000);
    assert(restarted.security.reserveOutgoingSequence(false, sequence) && sequence == 10000);
    sixBytesFromUInt64(1, configured);
    assert(restarted.security.property(PID_SEQUENCE_NUMBER_SENDING)->write(1, 1, configured) == 1);
    assert(restarted.security.nextSequenceNumber(false) == 10001);
    assert(restarted.security.reserveOutgoingSequence(false, sequence) && sequence == 10001);
    Fixture abruptRestart(platform);
    assert(abruptRestart.security.nextSequenceNumber(false) == 10000 + KNX_SECURE_SEQUENCE_RESERVATION);
}

static void provisioningErrorsAndExhaustionFailClosed()
{
    JournalPlatform platform;
    platform.provisioned = false;
    {
        Fixture missingKey(platform);
        uint64_t sequence;
        assert(!missingKey.security.isFactoryProvisioned());
        assert(!missingKey.security.toolKey());
        assert(!missingKey.security.reserveOutgoingSequence(true, sequence));
    }
    platform.provisioned = true;
    platform.readSucceeds = false;
    {
        Fixture unreadable(platform);
        uint64_t sequence;
        assert(unreadable.security.nextSequenceNumber(false) == 0);
        assert(!unreadable.security.reserveOutgoingSequence(false, sequence));
        assert(!unreadable.security.acceptIncomingSequence(true, 0x1234, 7));
    }
    platform.readSucceeds = true;
    {
        Fixture exhausted(platform);
        uint64_t sequence;
        const uint64_t maximum = UINT64_C(0xffffffffffff);
        assert(exhausted.security.ensureOutgoingSequenceAtLeast(false, maximum));
        assert(exhausted.security.reserveOutgoingSequence(false, sequence) && sequence == maximum);
        assert(exhausted.security.nextSequenceNumber(false) == 0);
        assert(!exhausted.security.reserveOutgoingSequence(false, sequence));
        assert(!exhausted.security.ensureOutgoingSequenceAtLeast(false, 1));
    }
    Fixture restarted(platform);
    assert(restarted.security.nextSequenceNumber(false) == 0);
}

static void unauthenticatedReplayQueriesCannotExhaustSenderCache()
{
    JournalPlatform platform;
    Fixture fixture(platform);
    for (unsigned index = 0; index < KNX_SECURE_TOOL_SENDERS + 32; ++index)
        assert(fixture.security.lastValidSequenceNumber(true, 0x1000 + index) == 0);
    assert(platform.commits == 0);
    assert(fixture.security.acceptIncomingSequence(true, 0x4321, 1));
    assert(fixture.security.lastValidSequenceNumber(true, 0x4321) == 1);
    // Reading a durable entry after reboot also remains non-mutating.
    Fixture restarted(platform);
    assert(restarted.security.lastValidSequenceNumber(true, 0x4321) == 1);
    for (unsigned index = 0; index < KNX_SECURE_TOOL_SENDERS + 32; ++index)
        assert(restarted.security.lastValidSequenceNumber(true, 0x2000 + index) == 0);
    assert(restarted.security.acceptIncomingSequence(true, 0x4321, 2));
    for (unsigned index = 0; index < KNX_SECURE_TOOL_SENDERS + 2; ++index)
        assert(restarted.security.acceptIncomingSequence(true, 0x3000 + index, 10));
    // Eviction is safe: a returning sender is checked against its durable floor.
    assert(restarted.security.lastValidSequenceNumber(true, 0x4321) == 2);
    assert(!restarted.security.acceptIncomingSequence(true, 0x4321, 2));
    assert(restarted.security.acceptIncomingSequence(true, 0x4321, 3));
    assert(!restarted.security.acceptIncomingSequence(true, 0x3000, 10));
}

static void resetPreservesNonceHistoryAndRestoresFactoryKey()
{
    JournalPlatform platform;
    uint64_t before = 0;
    Fixture fixture(platform);
    assert(fixture.security.reserveOutgoingSequence(true, before));
    assert(fixture.security.acceptIncomingSequence(true, 0x1234, 15));
    uint8_t changed[16];
    memset(changed, 0xa5, sizeof(changed));
    assert(fixture.security.property(PID_TOOL_KEY)->write(1, 1, changed) == 1);
    fixture.security.masterReset(FactoryReset, 0);
    assert(fixture.security.toolKey()[0] == 1 && fixture.security.toolKey()[15] == 16);
    assert(fixture.security.nextSequenceNumber(true) == before + 1);
    assert(fixture.security.lastValidSequenceNumber(true, 0x1234) == 15);
    uint64_t after;
    assert(fixture.security.reserveOutgoingSequence(true, after) && after > before);
}

static void realFailureCountersAndBoundedLog()
{
    JournalPlatform platform;
    Fixture fixture(platform);
    assert(fixture.security.getGroupObjectSecurity(0) == DataSecurity::None);
    for (unsigned count = 0; count < UINT16_MAX + 3U; ++count)
        fixture.security.recordFailure(3, 0x1234, 0x2345, 0x80, count);
    uint8_t request[3] = {0, 0, 0};
    uint8_t result[16] = {};
    uint8_t length = sizeof(result);
    fixture.security.state(PID_SECURITY_FAILURES_LOG, request, 3, result, length);
    assert(length == 11 && result[0] == ReturnCodes::Success);
    assert(getWord(result + 7) == UINT16_MAX); // crypto counter, saturated
    request[1] = 1;
    length = sizeof(result);
    fixture.security.state(PID_SECURITY_FAILURES_LOG, request, 3, result, length);
    assert(length == 15 && getWord(result + 3) == 0x1234 && getWord(result + 5) == 0x2345);
    assert(result[14] == 3);
    uint8_t bounded[4] = {0, 0, 0, 0x5a};
    length = 3;
    fixture.security.state(PID_SECURITY_FAILURES_LOG, request, 3, bounded, length);
    assert(length == 2 && bounded[3] == 0x5a);
    request[1] = 0;
    length = sizeof(result);
    fixture.security.command(PID_SECURITY_FAILURES_LOG, request, 3, result, length);
    assert(length == 2 && result[0] == ReturnCodes::Success);
    length = sizeof(result);
    fixture.security.state(PID_SECURITY_FAILURES_LOG, request, 3, result, length);
    assert(length == 11 && getWord(result + 7) == 0);
}

#ifdef KNX_SECURE_OPENSSL
static void fromHex(const char* encoded, uint8_t bytes[32])
{
    auto nibble = [](char value) -> uint8_t {
        return static_cast<uint8_t>(value >= 'a' ? value - 'a' + 10 : value - '0');
    };
    for (unsigned index = 0; index < 32; ++index)
        bytes[index] = static_cast<uint8_t>((nibble(encoded[index * 2]) << 4) | nibble(encoded[index * 2 + 1]));
}

static void auditedCryptoBackendMatchesIndependentVectors()
{
    JournalPlatform platform;
    uint8_t ownPrivate[32], peerPublic[32], expected[32], actual[32];
    // RFC 7748 section 6.1, Alice/Bob vectors, independent of this implementation.
    fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", ownPrivate);
    fromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", peerPublic);
    fromHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", expected);
    assert(platform.secureX25519(ownPrivate, peerPublic, actual));
    assert(memcmp(expected, actual, 32) == 0);
    uint8_t basePoint[32] = {9};
    fromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", expected);
    assert(platform.secureX25519(ownPrivate, basePoint, actual));
    assert(memcmp(expected, actual, 32) == 0);
    uint8_t invalidPoint[32] = {};
    memset(actual, 0x5a, sizeof(actual));
    assert(!platform.secureX25519(ownPrivate, invalidPoint, actual));
    assert(memcmp(actual, invalidPoint, 32) == 0);
    // SHA-256("abc"), FIPS 180-4 known-answer test.
    fromHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", expected);
    assert(platform.secureSha256(reinterpret_cast<const uint8_t*>("abc"), 3, actual));
    assert(memcmp(expected, actual, 32) == 0);
    assert(!platform.secureSha256(nullptr, 3, actual));
    assert(!platform.secureX25519(nullptr, peerPublic, actual));
}
#endif

int main()
{
    reservationsSurviveAbruptPowerLoss();
    failedCommitsNeverAuthorizeTraffic();
    replayStateIsSeparatedAndDurable();
    liveEtsSequenceFloorsAreMonotonicAndDurable();
    unauthenticatedReplayQueriesCannotExhaustSenderCache();
    provisioningErrorsAndExhaustionFailClosed();
    resetPreservesNonceHistoryAndRestoresFactoryKey();
    realFailureCountersAndBoundedLog();
#ifdef KNX_SECURE_OPENSSL
    auditedCryptoBackendMatchesIndependentVectors();
#endif
}
