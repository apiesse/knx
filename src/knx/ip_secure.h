#pragma once

#include "config.h"
#if defined(USE_IP) && defined(USE_IPSECURE)
#include "platform.h"
#include "ip_parameter_object.h"

// Fixed capacity is deliberate: no packet-controlled allocations in the security
// layer. Increase at compile time when a product needs larger KNXnet/IP packets.
#ifndef KNX_IPSECURE_MAX_FRAME
#define KNX_IPSECURE_MAX_FRAME 512
#endif
#ifndef KNX_IPSECURE_MAX_SESSIONS
#define KNX_IPSECURE_MAX_SESSIONS 8
#endif
#ifndef KNX_IPSECURE_REPLAY_CAPACITY
#define KNX_IPSECURE_REPLAY_CAPACITY 512
#endif
static_assert(KNX_IPSECURE_MAX_FRAME >= 56 && KNX_IPSECURE_MAX_FRAME <= 4118,
              "KNX IP Secure frame capacity must include a handshake and fit the CTR counter");

namespace KnxIpSecure
{
constexpr uint16_t Wrapper = 0x0950;
constexpr uint16_t SessionRequest = 0x0951;
constexpr uint16_t SessionResponse = 0x0952;
constexpr uint16_t SessionAuthenticate = 0x0953;
constexpr uint16_t SessionStatus = 0x0954;
constexpr uint16_t TimerNotify = 0x0955;
constexpr uint64_t MaxSequence = UINT64_C(0xffffffffffff);
constexpr uint16_t Overhead = 38;

bool validFrame(const uint8_t* packet, uint16_t length);
uint64_t read48(const uint8_t* bytes);
void write48(uint64_t value, uint8_t* bytes);
void erase(void* memory, size_t length);
bool equal(const uint8_t* a, const uint8_t* b, size_t length);
bool wrap(const uint8_t key[16], uint16_t session, uint64_t sequence,
          const uint8_t serial[6], uint16_t tag, const uint8_t* inner,
          uint16_t innerLength, uint8_t* output, uint16_t capacity, uint16_t& outputLength);
// Authenticated plaintext is released only after both MAC and inner header pass.
bool unwrap(const uint8_t key[16], const uint8_t* packet, uint16_t length,
            uint16_t expectedSession, uint8_t* inner, uint16_t capacity, uint16_t& innerLength);
void authenticationMac(const uint8_t key[16], const uint8_t header[8],
                       const uint8_t xorPublicKeys[32], uint8_t mac[16]);
bool timerNotify(const uint8_t key[16], uint64_t timer, const uint8_t serial[6],
                 uint16_t tag, uint8_t packet[36]);
bool verifyTimerNotify(const uint8_t key[16], const uint8_t* packet, uint16_t length);
}

class IpSecureSessionHandler
{
  public:
    virtual ~IpSecureSessionHandler() {}
    virtual void secureIpFrame(uint8_t* packet, uint16_t length, uint32_t address,
                               uint16_t port, uint16_t session) = 0;
    virtual void secureSessionClosed(uint16_t session) = 0;
};

class IpSecureSessions
{
  public:
    IpSecureSessions(Platform& platform, IpParameterObject& parameters, IpSecureSessionHandler& handler);
    ~IpSecureSessions();
    void enabled(bool value);
    void loop();
    bool receive(uint8_t* packet, uint16_t length, uint32_t address, uint16_t port, int tcp = -1);
    bool send(uint16_t session, uint8_t* packet, uint16_t length);
    bool authenticated(uint16_t session) const;
    uint16_t user(uint16_t session) const;
    bool isTcp(uint16_t session) const;
    bool endpoint(uint16_t session, uint32_t address, uint16_t port) const;
    void close(uint16_t session);
  private:
    struct Session
    {
        uint16_t id = 0;
        uint16_t user = 0;
        uint32_t address = 0;
        uint16_t port = 0;
        int tcp = -1;
        uint8_t key[16] = {};
        uint8_t xorPublic[32] = {};
        uint8_t deviceCredential[16] = {};
        uint8_t userCredential[16] = {};
        uint8_t serial[6] = {};
        uint64_t sendSequence = 0;
        uint64_t receiveSequence = 0;
        bool received = false;
        uint32_t lastActivity = 0;
    };
    struct Stream
    {
        int connection = -1;
        uint32_t address = 0;
        uint16_t port = 0;
        uint16_t used = 0;
        uint32_t lastActivity = 0;
        uint8_t data[KNX_IPSECURE_MAX_FRAME] = {};
    };
    Session* find(uint16_t id);
    const Session* find(uint16_t id) const;
    bool sendRaw(Session& session, uint8_t* packet, uint16_t length);
    void status(Session& session, uint8_t value);
    void request(uint8_t* packet, uint16_t length, uint32_t address, uint16_t port, int tcp);
    void closeStream(Stream& stream);
    void releaseSession(Session& session);
    bool credentialsCurrent(const Session& session);
    Platform& _platform;
    IpParameterObject& _parameters;
    IpSecureSessionHandler& _handler;
    Session _sessions[KNX_IPSECURE_MAX_SESSIONS];
    Stream _streams[KNX_IPSECURE_MAX_SESSIONS];
    uint16_t _nextId = 0;
    uint8_t _serial[6] = {};
    bool _enabled = false;
    bool _listener = false;
};

class IpSecureRouting
{
  public:
    IpSecureRouting(Platform& platform, IpParameterObject& parameters);
    void enabled(bool value);
    void loop();
    bool send(uint8_t* packet, uint16_t length);
    // Returns the authenticated inner frame, or zero when consumed/rejected.
    uint16_t receive(uint8_t* packet, uint16_t length);
    bool required() const;
  private:
    bool configure();
    bool randomDelay(uint32_t low, uint32_t high, uint32_t& value);
    void advance();
    bool reserve(uint64_t timer);
    void schedule(bool periodic);
    bool notify();
    void synchronize(uint64_t remoteTimer, const uint8_t serial[6], uint16_t tag, bool notification);
    Platform& _platform;
    IpParameterObject& _parameters;
    uint8_t _key[16] = {};
    uint8_t _serial[6] = {};
    uint8_t _notifySerial[6] = {};
    uint32_t _tag = 0;
    uint64_t _tagTimer = 0;
    uint16_t _notifyTag = 0;
    uint64_t _timer = 0;
    uint64_t _reserved = 0;
    uint32_t _lastClock = 0;
    uint32_t _startClock = 0;
    uint32_t _notifyAt = 0;
    uint32_t _multicast = 0;
    uint8_t _latencyFraction = 0;
    uint16_t _latency = 2000;
    uint16_t _syncLatency = 204;
    bool _enabled = false;
    bool _configured = false;
    bool _synchronized = false;
    bool _keeper = false;
    bool _periodic = true;
    bool _initialNotified = false;
    struct Replay
    {
        bool used = false;
        uint64_t timer = 0;
        uint16_t tag = 0;
        uint8_t serial[6] = {};
    };
    Replay _replay[KNX_IPSECURE_REPLAY_CAPACITY];
};
#endif
