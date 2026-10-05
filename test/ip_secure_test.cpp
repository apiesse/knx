#include "knx/ip_secure.h"
#include "knx/bits.h"
#include "knx/bau_systemB_coupler.h"
#include "knx/cemi_server.h"
#include "knx/ip_tunnel_server.h"
#include "knx/ip_data_link_layer.h"
#include "knx/knx_ip_frame.h"
#include "knx/knx_ip_connect_response.h"
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <map>
#include <vector>
#include <string>

static uint32_t now = 0;
uint32_t millis() { return now; }
void delay(uint32_t value) { now += value; }
void delayMicroseconds(unsigned int) {}
void pinMode(uint32_t, uint32_t) {}
void digitalWrite(uint32_t, uint32_t) {}
uint32_t digitalRead(uint32_t) { return 0; }
void attachInterrupt(uint32_t, voidFuncPtr, uint32_t) {}

static std::vector<uint8_t> hex(const char* value)
{
    std::vector<uint8_t> result;
    while (*value)
    {
        char pair[3] = {value[0], value[1], 0}; result.push_back(std::strtoul(pair, nullptr, 16)); value += 2;
    }
    return result;
}
static void releaseProperties(InterfaceObject& object)
{
    std::vector<Property*> properties;
    for (unsigned id = 0; id < 256; ++id) if (auto* property = object.property(static_cast<PropertyID>(id))) properties.push_back(property);
    for (auto* property : properties) delete property;
}
class FakePlatform : public Platform
{
  public:
    std::vector<std::vector<uint8_t>> sent, multicast, tcpSent;
    std::map<uint32_t, std::vector<uint8_t>> journal;
    std::vector<uint8_t> tcpInput;
    bool randomOk = true, durableOk = true, accept = false, tcpClosed = false;
    unsigned writes = 0;
    void restart() override {}
    void fatalError() override { std::abort(); }
    void macAddress(uint8_t* bytes) override { const uint8_t serial[6] = {0x11,0x22,0x33,0x44,0x55,0x66}; memcpy(bytes, serial, 6); }
    bool fillRandom(uint8_t* bytes, size_t length) override
    {
        if (!randomOk) return false;
        const auto privateKey = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        for (size_t i = 0; i < length; ++i) bytes[i] = privateKey[i % 32]; return true;
    }
    bool sendBytesUniCast(uint32_t, uint16_t, uint8_t* bytes, uint16_t length) override
    { sent.emplace_back(bytes, bytes + length); return true; }
    bool sendBytesMultiCast(uint8_t* bytes, uint16_t length) override
    { multicast.emplace_back(bytes, bytes + length); return true; }
    int readSecurityState(uint32_t id, uint8_t* bytes, size_t capacity) override
    {
        const auto found = journal.find(id); if (found == journal.end()) return 0;
        if (found->second.size() > capacity) return -1;
        memcpy(bytes, found->second.data(), found->second.size()); return found->second.size();
    }
    bool writeSecurityState(uint32_t id, const uint8_t* bytes, size_t length) override
    { if (!durableOk) return false; journal[id] = std::vector<uint8_t>(bytes, bytes + length); ++writes; return true; }
    bool setupSecureTcp(uint16_t) override { return true; }
    int acceptSecureTcp(uint32_t& address, uint16_t& port) override
    { if (!accept) return -1; accept = false; address = 0x0a000001; port = 50000; return 7; }
    int readSecureTcp(int, uint8_t* bytes, uint16_t capacity) override
    {
        const size_t length = tcpInput.size() < capacity ? tcpInput.size() : capacity;
        if (!length) return 0; memcpy(bytes, tcpInput.data(), length); tcpInput.erase(tcpInput.begin(), tcpInput.begin() + length); return length;
    }
    bool sendSecureTcp(int, uint8_t* bytes, uint16_t length) override
    { tcpSent.emplace_back(bytes, bytes + length); return true; }
    void closeSecureTcp(int) override { tcpClosed = true; }
};
class Handler : public IpSecureSessionHandler
{
  public:
    unsigned received = 0, closed = 0;
    uint16_t session = 0;
    void secureIpFrame(uint8_t*, uint16_t, uint32_t, uint16_t, uint16_t id) override { ++received; session = id; }
    void secureSessionClosed(uint16_t) override { ++closed; }
};
class IntegrationBau : public BauSystemBCoupler
{
  public:
    IpParameterObject& ip;
    CemiServer cemi;
    IpTunnelServer server;
    IpDataLinkLayer discovery;
    IntegrationBau(FakePlatform& platform, IpParameterObject& parameters)
        : BauSystemBCoupler(platform), ip(parameters), cemi(*this, server), server(_deviceObj, parameters, platform, cemi),
          discovery(_deviceObj, parameters, _netLayer.getPrimaryInterface(), platform, *this, server)
    { _deviceObj.individualAddress(0x1100); _deviceObj.bauNumber(0x11223344); discovery.enabled(true); }
    ~IntegrationBau() { discovery.enabled(false); releaseProperties(_deviceObj); releaseProperties(_appProgram); }
    bool enabled() override { return true; }
    void enabled(bool) override {}
    InterfaceObject* getInterfaceObject(uint8_t index) override
    { if (index == 3) return &ip; return &_deviceObj; }
    InterfaceObject* getInterfaceObject(ObjectType type, uint16_t) override
    { if (type == OT_IP_PARAMETER) return &ip; return &_deviceObj; }
};
struct Fixture
{
    FakePlatform platform;
    DeviceObject device;
    IpParameterObject parameters;
    Handler handler;
    Fixture() : parameters(device, platform)
    {
        device.bauNumber(0x11223344);
        const auto key = hex("000102030405060708090a0b0c0d0e0f");
        uint8_t count = 1;
        parameters.writeProperty(PID_DEVICE_AUTHENTICATION, 1, const_cast<uint8_t*>(key.data()), count); assert(count == 1);
        count = 1; parameters.writeProperty(PID_BACKBONE_KEY, 1, const_cast<uint8_t*>(key.data()), count); assert(count == 1);
        count = 1; parameters.writeProperty(PID_USER_PASSWORD_HASHES, 1, const_cast<uint8_t*>(key.data()), count); assert(count == 1);
        count = 1; parameters.writeProperty(PID_USER_PASSWORD_HASHES, 2, const_cast<uint8_t*>(key.data()), count); assert(count == 1);
        uint8_t user[2] = {2, 1}; count = 1; parameters.writeProperty(PID_TUNNELING_USERS, 1, user, count); assert(count == 1);
    }
    ~Fixture() { releaseProperties(parameters); releaseProperties(device); }
};
static std::vector<uint8_t> sessionRequest(bool tcp = false)
{
    auto request = hex("06100951002e0801000000000000");
    request[7] = tcp ? 2 : 1;
    const auto alicePublic = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    request.insert(request.end(), alicePublic.begin(), alicePublic.end()); return request;
}
static uint16_t establish(Fixture& fixture, IpSecureSessions& sessions, uint8_t sessionKey[16], uint8_t xorPublic[32], bool tcp = false)
{
    auto request = sessionRequest(tcp);
    if (tcp)
    {
        fixture.platform.accept = true;
        // Verify TCP framing across a partial header and body boundary.
        fixture.platform.tcpInput.assign(request.begin(), request.begin() + 3); sessions.loop();
        assert(fixture.platform.tcpSent.empty());
        fixture.platform.tcpInput.assign(request.begin() + 3, request.end()); sessions.loop();
    }
    else assert(sessions.receive(request.data(), request.size(), 0x0a000001, 50000));
    const auto& response = tcp ? fixture.platform.tcpSent.back() : fixture.platform.sent.back();
    assert(response.size() == 56 && getWord(response.data() + 2) == KnxIpSecure::SessionResponse);
    const auto alicePrivate = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    uint8_t shared[32], digest[32];
    assert(fixture.platform.secureX25519(alicePrivate.data(), response.data() + 8, shared));
    const auto expectedShared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert(KnxIpSecure::equal(shared, expectedShared.data(), 32));
    assert(fixture.platform.secureSha256(shared, 32, digest)); memcpy(sessionKey, digest, 16);
    for (unsigned i = 0; i < 32; ++i) xorPublic[i] = response[8 + i] ^ request[14 + i];
    const auto key = hex("000102030405060708090a0b0c0d0e0f"); uint8_t mac[16];
    KnxIpSecure::authenticationMac(key.data(), response.data(), xorPublic, mac);
    assert(KnxIpSecure::equal(mac, response.data() + 40, 16));
    return getWord(response.data() + 6);
}
static std::vector<uint8_t> authenticatedPacket(const uint8_t key[16], uint16_t session, uint64_t sequence,
                                                const std::vector<uint8_t>& inner)
{
    std::vector<uint8_t> packet(inner.size() + KnxIpSecure::Overhead); uint16_t length;
    const uint8_t serial[6] = {};
    assert(KnxIpSecure::wrap(key, session, sequence, serial, 0, inner.data(), inner.size(), packet.data(), packet.size(), length));
    assert(length == packet.size()); return packet;
}
static void authenticate(Fixture& fixture, IpSecureSessions& sessions, uint16_t id, const uint8_t key[16], const uint8_t xorPublic[32], bool tcp = false)
{
    auto auth = hex("061009530018000200000000000000000000000000000000");
    const auto userKey = hex("000102030405060708090a0b0c0d0e0f");
    KnxIpSecure::authenticationMac(userKey.data(), auth.data(), xorPublic, auth.data() + 8);
    auto packet = authenticatedPacket(key, id, 0, auth);
    if (tcp) { fixture.platform.tcpInput = packet; sessions.loop(); }
    else assert(sessions.receive(packet.data(), packet.size(), 0x0a000001, 50000));
    assert(sessions.authenticated(id) && sessions.user(id) == 2);
}
static void codecTest()
{
    const auto key = hex("000102030405060708090a0b0c0d0e0f");
    const auto inner = hex("061002070010010008010a0000010e57");
    const uint8_t serial[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t packet[512], plaintext[512]; uint16_t length, plainLength;
    assert(KnxIpSecure::wrap(key.data(), 0x1234, UINT64_C(0x010203040506), serial, 0,
                            inner.data(), inner.size(), packet, sizeof(packet), length));
    const auto wrapperVector = hex("061009500036123401020304050611223344556600007c3dd807c749a08467267a27c0ec8b69b8427b1a857f3b8be8fd4e39f1dc78f7");
    assert(length == wrapperVector.size() && !memcmp(packet, wrapperVector.data(), length));
    assert(KnxIpSecure::unwrap(key.data(), packet, length, 0x1234, plaintext, sizeof(plaintext), plainLength));
    assert(plainLength == inner.size() && !memcmp(plaintext, inner.data(), plainLength));
    // Every byte in the wrapper is authenticated, including header/session/nonce.
    for (uint16_t i = 0; i < length; ++i)
    {
        packet[i] ^= 1; memset(plaintext, 0xa5, sizeof(plaintext));
        assert(!KnxIpSecure::unwrap(key.data(), packet, length, 0x1234, plaintext, sizeof(plaintext), plainLength));
        assert(plainLength == 0 && plaintext[0] == 0xa5); packet[i] ^= 1;
    }
    for (uint16_t size = 0; size < length; ++size)
        assert(!KnxIpSecure::unwrap(key.data(), packet, size, 0x1234, plaintext, sizeof(plaintext), plainLength));
    assert(!KnxIpSecure::wrap(key.data(), 1, KnxIpSecure::MaxSequence + 1, serial, 0, inner.data(), inner.size(), packet, sizeof(packet), length));
    assert(!KnxIpSecure::wrap(key.data(), 1, 0, serial, 0, inner.data(), inner.size(), packet, 53, length));
    uint8_t timer[36];
    assert(KnxIpSecure::timerNotify(key.data(), 0x010203040506, serial, 0x7788, timer));
    const auto timerVector = hex("061009550024010203040506112233445566778845274869d1d8b132c8dc7cbd4c722af0");
    assert(!memcmp(timer, timerVector.data(), sizeof(timer)));
    assert(KnxIpSecure::verifyTimerNotify(key.data(), timer, sizeof(timer)));
    for (unsigned i = 0; i < sizeof(timer); ++i)
    { timer[i] ^= 1; assert(!KnxIpSecure::verifyTimerNotify(key.data(), timer, sizeof(timer))); timer[i] ^= 1; }
    const auto authHeader = hex("0610095200381234"), xorPublic = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    uint8_t authMac[16]; KnxIpSecure::authenticationMac(key.data(), authHeader.data(), xorPublic.data(), authMac);
    const auto authVector = hex("820266bb9759605c569c097e140dcd41"); assert(!memcmp(authMac, authVector.data(), 16));
}
static void sessionTest(bool tcp)
{
    now = 100;
    Fixture fixture; IpSecureSessions sessions(fixture.platform, fixture.parameters, fixture.handler); sessions.enabled(true);
    uint8_t key[16], xorPublic[32]; const uint16_t id = establish(fixture, sessions, key, xorPublic, tcp);
    authenticate(fixture, sessions, id, key, xorPublic, tcp);
    auto inner = hex("06100207001001000801000000000000");
    auto packet = authenticatedPacket(key, id, 1, inner);
    if (tcp) { fixture.platform.tcpInput = packet; sessions.loop(); }
    else sessions.receive(packet.data(), packet.size(), 0x0a000001, 50000);
    assert(fixture.handler.received == 1 && fixture.handler.session == id);
    if (tcp) { fixture.platform.tcpInput = packet; sessions.loop(); }
    else sessions.receive(packet.data(), packet.size(), 0x0a000001, 50000);
    assert(fixture.handler.received == 1); // Replay rejected.
    packet = authenticatedPacket(key, id, 2, inner);
    sessions.receive(packet.data(), packet.size(), 0x0a000002, 50000, tcp ? 7 : -1);
    assert(fixture.handler.received == 1); // Authenticated data at wrong endpoint rejected.
    packet.back() ^= 1;
    sessions.receive(packet.data(), packet.size(), 0x0a000001, 50000, tcp ? 7 : -1);
    assert(fixture.handler.received == 1); packet.back() ^= 1;
    sessions.receive(packet.data(), packet.size(), 0x0a000001, 50000, tcp ? 7 : -1);
    assert(fixture.handler.received == 2); // Invalid MAC did not consume sequence2.
    now += 60001; sessions.loop(); assert(!sessions.authenticated(id) && fixture.handler.closed == 1);
    // Low-order X25519 public keys must never result in an active session.
    const size_t sends = fixture.platform.sent.size(); auto invalid = sessionRequest(); memset(invalid.data() + 14, 0, 32);
    sessions.receive(invalid.data(), invalid.size(), 0x0a000003, 50001); assert(fixture.platform.sent.size() == sends);
    sessions.enabled(false);
}
static void routingTest()
{
    now = 0; Fixture fixture;
    assert(fixture.parameters.secureServiceFamilies((1U << 3) | (1U << 4) | (1U << 5)));
    assert(fixture.parameters.tunnelingUser(1) && fixture.parameters.tunnelingUser(2) && !fixture.parameters.tunnelingUser(3));
    IpSecureRouting routing(fixture.platform, fixture.parameters); routing.enabled(true);
    auto inner = hex("061005300006");
    assert(!routing.send(inner.data(), inner.size()));
    assert(fixture.platform.multicast.size() == 1 && getWord(fixture.platform.multicast[0].data() + 2) == KnxIpSecure::TimerNotify);
    assert(!routing.send(inner.data(), inner.size()) && fixture.platform.multicast.size() == 1);
    now = 7000; routing.loop(); assert(routing.send(inner.data(), inner.size()));
    auto packet = fixture.platform.multicast.back(); const uint64_t firstTimer = KnxIpSecure::read48(packet.data() + 8);
    auto repeated = packet; assert(routing.receive(packet.data(), packet.size()) == inner.size());
    assert(routing.receive(repeated.data(), repeated.size()) == 0);
    const auto key = hex("000102030405060708090a0b0c0d0e0f"); const uint8_t serial[6] = {1,2,3,4,5,6};
    uint8_t stale[512]; uint16_t length;
    assert(KnxIpSecure::wrap(key.data(), 0, firstTimer - 3000, serial, 1, inner.data(), inner.size(), stale, sizeof(stale), length));
    assert(routing.receive(stale, length) == 0);
    IpSecureRouting rebooted(fixture.platform, fixture.parameters); rebooted.enabled(true); now += 7000; rebooted.loop();
    now += 7000; rebooted.loop(); assert(rebooted.send(inner.data(), inner.size()));
    assert(KnxIpSecure::read48(fixture.platform.multicast.back().data() + 8) > firstTimer);
    const uint64_t beforeRotation = KnxIpSecure::read48(fixture.platform.multicast.back().data() + 8);
    uint8_t newKey[16] = {1}, count = 1;
    fixture.parameters.writeProperty(PID_BACKBONE_KEY, 1, newKey, count); assert(count == 1);
    assert(!rebooted.send(inner.data(), inner.size()));
    now += 7000; rebooted.loop(); assert(rebooted.send(inner.data(), inner.size()));
    assert(KnxIpSecure::read48(fixture.platform.multicast.back().data() + 8) < beforeRotation);
    const size_t beforeRollback = fixture.platform.multicast.size();
    count = 1; fixture.parameters.writeProperty(PID_BACKBONE_KEY, 1, const_cast<uint8_t*>(key.data()), count);
    assert(!rebooted.send(inner.data(), inner.size()));
    now += 7000; rebooted.loop(); assert(!rebooted.send(inner.data(), inner.size()));
    assert(fixture.platform.multicast.size() == beforeRollback);
    count = 1; fixture.parameters.writeProperty(PID_BACKBONE_KEY, 1, newKey, count);
    uint8_t group[4] = {0xe0,0,0x17,0x0d}; count = 1;
    fixture.parameters.writeProperty(PID_ROUTING_MULTICAST_ADDRESS, 1, group, count);
    const size_t oldGroupSends = fixture.platform.multicast.size();
    assert(!rebooted.send(inner.data(), inner.size()) && fixture.platform.multicast.size() == oldGroupSends);
    group[3] = 0x0c; count = 1; fixture.parameters.writeProperty(PID_ROUTING_MULTICAST_ADDRESS, 1, group, count);
    fixture.platform.durableOk = false; IpSecureRouting failClosed(fixture.platform, fixture.parameters); failClosed.enabled(true);
    const size_t before = fixture.platform.multicast.size(); assert(!failClosed.send(inner.data(), inner.size()));
    assert(fixture.platform.multicast.size() == before);
    fixture.platform.durableOk = true; fixture.platform.journal[0x100000] = {1,2,3};
    IpSecureRouting corrupt(fixture.platform, fixture.parameters); corrupt.enabled(true);
    assert(!corrupt.send(inner.data(), inner.size()));
    fixture.platform.journal.clear(); fixture.platform.randomOk = false;
    IpSecureRouting noRandom(fixture.platform, fixture.parameters); noRandom.enabled(true);
    assert(!noRandom.send(inner.data(), inner.size()) && fixture.platform.journal.empty());
}
static void profileTest()
{
    Fixture fixture;
    uint8_t serial[6]; assert(fixture.parameters.securitySerialNumber(serial));
    assert(!memcmp(serial, "\x00\xfa\x11\x22\x33\x44", 6));
    fixture.device.bauNumber(0x01020304);
    assert(!fixture.parameters.securitySerialNumber(serial));
    fixture.device.bauNumber(0x11223344);
    uint8_t bytes[2] = {}; uint8_t count = 1;
    fixture.parameters.readProperty(PID_TUNNELING_ADDRESSES, 0, count, bytes);
    assert(count == 1 && getWord(bytes) == KNX_TUNNELING);
    count = 1; fixture.parameters.readProperty(PID_TUNNELING_ADDRESSES, 1, count, bytes);
    assert(count == 1 && bytes[0] == 1);
    assert(fixture.parameters.tunnelingUser(2, 1));
    assert(!fixture.parameters.tunnelingUser(2, KNX_TUNNELING + 1));
    const auto valid = hex("0201"), invalidIndex = hex("0200"), invalidUser = hex("0101");
    for (const auto& entry : {invalidIndex, invalidUser})
    {
        assert(fixture.parameters.property(PID_TUNNELING_USERS)->write(1, 1, entry.data()) == 1);
        assert(!fixture.parameters.tunnelingUser(2));
    }
    assert(fixture.parameters.property(PID_TUNNELING_USERS)->write(1, 1, valid.data()) == 1);
    assert(fixture.parameters.tunnelingUser(2));
    const auto unsorted = hex("03010201");
    assert(fixture.parameters.property(PID_TUNNELING_USERS)->write(1, 2, unsorted.data()) == 2);
    assert(!fixture.parameters.tunnelingUser(2) && !fixture.parameters.tunnelingUser(3));
    assert(fixture.parameters.tunnelingUser(1)); // Administrator has access to all slots.
}
static void revocationTest(uint8_t reason)
{
    now = 0; Fixture fixture;
    IpSecureSessions sessions(fixture.platform, fixture.parameters, fixture.handler); sessions.enabled(true);
    uint8_t key[16], xorPublic[32]; const uint16_t id = establish(fixture, sessions, key, xorPublic);
    authenticate(fixture, sessions, id, key, xorPublic);
    uint8_t replacement[16] = {1}, count = 1;
    if (reason == 2) fixture.device.bauNumber(0x11223345);
    else fixture.parameters.writeProperty(reason ? PID_DEVICE_AUTHENTICATION : PID_USER_PASSWORD_HASHES,
                                          reason ? 1 : 2, replacement, count);
    assert(count == 1);
    auto inner = hex("06100207001001000801000000000000");
    auto packet = authenticatedPacket(key, id, 1, inner);
    sessions.receive(packet.data(), packet.size(), 0x0a000001, 50000);
    assert(!sessions.authenticated(id) && fixture.handler.received == 0 && fixture.handler.closed == 1);
}
static void lateIdentityTest()
{
    now = 0; Fixture fixture; fixture.device.bauNumber(0x01020304);
    IpSecureSessions sessions(fixture.platform, fixture.parameters, fixture.handler);
    IpSecureRouting routing(fixture.platform, fixture.parameters);
    sessions.enabled(true); routing.enabled(true);
    auto request = sessionRequest();
    sessions.receive(request.data(), request.size(), 0x0a000001, 50000);
    assert(fixture.platform.sent.empty()); // Shared development serial fails closed.
    fixture.device.bauNumber(0x11223344); // Factory identity arrives after object construction.
    uint8_t key[16], xorPublic[32]; const uint16_t id = establish(fixture, sessions, key, xorPublic);
    authenticate(fixture, sessions, id, key, xorPublic);
    assert(!memcmp(fixture.platform.sent.back().data() + 14, "\x00\xfa\x11\x22\x33\x44", 6));
    assert(fixture.parameters.secureServiceFamilies(1U << 5));
    auto inner = hex("061005300006"); assert(!routing.send(inner.data(), inner.size()));
    now = 7000; routing.loop(); assert(routing.send(inner.data(), inner.size()));
    assert(!memcmp(fixture.platform.multicast.back().data() + 14, "\x00\xfa\x11\x22\x33\x44", 6));
    const size_t before = fixture.platform.multicast.size();
    fixture.device.bauNumber(0x11223345); // The current group key is bound to its original identity.
    assert(!routing.send(inner.data(), inner.size()) && fixture.platform.multicast.size() == before);
    sessions.loop(); assert(!sessions.authenticated(id));
}
static void tunnelIntegrationTest(bool tcp)
{
    now = 0; Fixture fixture; IntegrationBau bau(fixture.platform, fixture.parameters);
    auto& server = bau.server; server.secureEnabled(true);
    assert(fixture.parameters.secureServiceFamilies((1U << 3) | (1U << 4)));
    uint32_t address = 0x0a000001; uint16_t port = 50000;
    auto submit = [&](std::vector<uint8_t> packet) {
        if (tcp) { fixture.platform.tcpInput = packet; server.loop(); }
        else assert(server.HandleIpFrame(packet.data(), packet.size(), address, port));
    };
    auto& sent = tcp ? fixture.platform.tcpSent : fixture.platform.sent;
    const auto connect = tcp ? hex("06100205001a0802000000000000080200000000000004040200") :
                               hex("06100205001a0801000000000000080100000000000004040200");
    // Plain connect cannot create a channel when service-family security is required.
    auto plain = connect; server.HandleIpFrame(plain.data(), plain.size(), address, port);
    assert(server.tunnelConnections()[0].ChannelId == 0);
    if (tcp) fixture.platform.accept = true;
    submit(sessionRequest(tcp));
    const auto response = sent.back(); assert(response.size() == 56);
    const uint16_t id = getWord(response.data() + 6);
    const auto privateKey = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const auto userKey = hex("000102030405060708090a0b0c0d0e0f");
    auto request = sessionRequest(tcp); uint8_t shared[32], digest[32], xorPublic[32];
    assert(fixture.platform.secureX25519(privateKey.data(), response.data() + 8, shared));
    assert(fixture.platform.secureSha256(shared, 32, digest));
    for (unsigned i = 0; i < 32; ++i) xorPublic[i] = response[8 + i] ^ request[14 + i];
    auto auth = hex("061009530018000200000000000000000000000000000000");
    KnxIpSecure::authenticationMac(userKey.data(), auth.data(), xorPublic, auth.data() + 8);
    submit(authenticatedPacket(digest, id, 0, auth));
    uint8_t inner[512]; uint16_t length;
    assert(KnxIpSecure::unwrap(digest, sent.back().data(), sent.back().size(), id, inner, sizeof(inner), length));
    assert(getWord(inner + 2) == KnxIpSecure::SessionStatus && inner[6] == 0);
    submit(authenticatedPacket(digest, id, 1, connect));
    const auto& tunnel = server.tunnelConnections()[0];
    assert(tunnel.ChannelId && tunnel.SecureSessionId == id);
    assert(KnxIpSecure::unwrap(digest, sent.back().data(), sent.back().size(), id, inner, sizeof(inner), length));
    assert(getWord(inner + 2) == ConnectResponse && inner[7] == 0 && inner[9] == (tcp ? 2 : 1));
    // Authenticated tunnelling user cannot create a device-management channel.
    auto management = tcp ? hex("061002050018080200000000000008020000000000000203") :
                            hex("061002050018080100000000000008010000000000000203");
    submit(authenticatedPacket(digest, id, 2, management));
    assert(KnxIpSecure::unwrap(digest, sent.back().data(), sent.back().size(), id, inner, sizeof(inner), length));
    assert(getWord(inner + 2) == ConnectResponse && inner[7] == E_AUTHORISATION_ERROR);
    auto state = tcp ? hex("06100207001001000802000000000000") : hex("06100207001001000801000000000000"); state[6] = tunnel.ChannelId;
    const size_t before = sent.size(); auto forged = state;
    server.HandleIpFrame(forged.data(), forged.size(), address, port); assert(sent.size() == before);
    submit(authenticatedPacket(digest, id, 3, state));
    assert(KnxIpSecure::unwrap(digest, sent.back().data(), sent.back().size(), id, inner, sizeof(inner), length));
    assert(getWord(inner + 2) == ConnectionStateResponse && inner[7] == 0);
    // Asynchronous outbound traffic must use this tunnel's session, independent
    // of whichever client most recently caused a synchronous server callback.
    CemiFrame frame(2); frame.messageCode(L_data_ind); frame.sourceAddress(0x1101); frame.destinationAddress(0x1102);
    frame.apdu().type(GroupValueWrite); server.dataRequestToChannelId(frame, tunnel.ChannelId);
    assert(KnxIpSecure::unwrap(digest, sent.back().data(), sent.back().size(), id, inner, sizeof(inner), length));
    assert(getWord(inner + 2) == TunnelingRequest);
    // When no security is required for management, any authenticated session
    // may open it (ISO 22510 Table44); this does not grant SAL tool privileges.
    assert(fixture.parameters.secureServiceFamilies(0));
    submit(authenticatedPacket(digest, id, 4, management));
    assert(KnxIpSecure::unwrap(digest, sent.back().data(), sent.back().size(), id, inner, sizeof(inner), length));
    assert(getWord(inner + 2) == ConnectResponse && inner[7] == 0);
    const uint8_t configChannel = inner[6];
    uint64_t clientSequence = 5;
    CemiFrame readRequest(2); readRequest.apdu().type(DeviceDescriptorRead);
    for (bool connected : {false, true})
    {
        std::vector<uint8_t> local(readRequest.apdu().length() + 20, 0);
        local[0] = 6; local[1] = 0x10; pushWord(DeviceConfigurationRequest, local.data() + 2);
        pushWord(local.size(), local.data() + 4); local[6] = 4; local[7] = configChannel;
        local[8] = tcp ? 0 : connected ? 1 : 0;
        local[10] = connected ? T_data_connected_req : T_data_individual_req;
        local[18] = readRequest.apdu().length();
        memcpy(local.data() + 19, readRequest.apdu().data() - 1, readRequest.apdu().length() + 1);
        assert(CemiFrame::validBuffer(local.data() + 10, local.size() - 10));
        submit(authenticatedPacket(digest, id, clientSequence++, local));
        assert(KnxIpSecure::unwrap(digest, sent.back().data(), sent.back().size(), id, inner, sizeof(inner), length));
        assert(getWord(inner + 2) == DeviceConfigurationRequest && inner[7] == configChannel);
        assert(inner[10] == (connected ? T_data_connected_ind : T_data_individual_ind));
        assert(CemiFrame::validBuffer(inner + 10, length - 10));
        assert((inner[19] & 0xfc) == 0); // Local TPCI never borrows a bus connection.
        assert(((inner[19] & 3) << 8 | inner[20]) == DeviceDescriptorResponse);
    }
    // Discovery is available to every authenticated user and its responses
    // remain inside the requesting session, including extended-search DIBs.
    auto search = tcp ? hex("0610020b00110802000000000000038407") : hex("0610020b00110801000000000000038407");
    submit(authenticatedPacket(digest, id, clientSequence++, search));
    assert(KnxIpSecure::unwrap(digest, sent.back().data(), sent.back().size(), id, inner, sizeof(inner), length));
    assert(getWord(inner + 2) == SearchResponseExt && inner[7] == (tcp ? 2 : 1));
    bool securityFamily = false, protectedFamilies = false, tunnelInfo = false;
    for (unsigned offset = 14; offset < length; offset += inner[offset])
    {
        assert(inner[offset] >= 2 && offset + inner[offset] <= length);
        if (inner[offset + 1] == 2)
            for (unsigned pair = offset + 2; pair < offset + inner[offset]; pair += 2)
                if (inner[pair] == 9) { securityFamily = true; assert(inner[pair + 1] == 1); }
        if (inner[offset + 1] == 6) protectedFamilies = true;
        if (inner[offset + 1] == 7) { tunnelInfo = true; assert(inner[offset + 7] & 2); }
    }
    assert(securityFamily && tunnelInfo && !protectedFamilies); // No enforced families at this point.
    assert(fixture.parameters.secureServiceFamilies((1U << 3) | (1U << 4)));
    submit(authenticatedPacket(digest, id, clientSequence++, search));
    assert(KnxIpSecure::unwrap(digest, sent.back().data(), sent.back().size(), id, inner, sizeof(inner), length));
    protectedFamilies = false;
    for (unsigned offset = 14; offset < length; offset += inner[offset])
        if (inner[offset + 1] == 6)
        {
            assert(inner[offset] == 6 && !memcmp(inner + offset + 2, "\x03\x01\x04\x01", 4));
            protectedFamilies = true;
        }
    assert(protectedFamilies); // Literal DIB type0x06 is distinct from Security family0x09.
    if (!tcp)
    {
        auto classic = hex("06100201000e0801000000000000");
        submit(authenticatedPacket(digest, id, clientSequence++, classic));
        assert(KnxIpSecure::unwrap(digest, sent.back().data(), sent.back().size(), id, inner, sizeof(inner), length));
        assert(getWord(inner + 2) == SearchResponse);
        const unsigned supported = 14 + LEN_DEVICE_INFORMATION_DIB;
        for (unsigned pair = supported + 2; pair < supported + inner[supported]; pair += 2) assert(inner[pair] != 9);
    }
    // A changed user/slot assignment immediately revokes an existing tunnel.
    const auto denied = hex("0301");
    assert(fixture.parameters.property(PID_TUNNELING_USERS)->write(1, 1, denied.data()) == 1);
    server.loop(); assert(server.tunnelConnections()[0].ChannelId == 0);
    now = 60001; server.loop(); assert(server.tunnelConnections()[0].ChannelId == 0);
    server.secureEnabled(false);
}
int main()
{
    codecTest(); profileTest(); sessionTest(false); sessionTest(true); routingTest();
    revocationTest(0); revocationTest(1); revocationTest(2); lateIdentityTest();
    tunnelIntegrationTest(false); tunnelIntegrationTest(true);
}
