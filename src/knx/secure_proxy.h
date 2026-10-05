#pragma once

#include "config.h"
#ifdef USE_DATASECURE
#include "cemi_frame.h"

class SecureApplicationLayer;

// Trusted local configuration. These are API fields, not AN192 wire bits.
// Standard PID81 records require an application-supplied, qualified decoder.
struct SecureProxyRule
{
    uint16_t groupAddress = 0;
    bool primarySecure = false;
    bool secondarySecure = false;
    bool primaryToSecondary = false;
    bool secondaryToPrimary = false;
    uint8_t key[16] = {};
};

enum class SecureProxyResult { ForwardUnchanged, Translated, Drop };

class SecureProxy
{
public:
    static constexpr uint16_t MaxRules = 50;
    explicit SecureProxy(SecureApplicationLayer& layer) : _layer(layer) {}
    ~SecureProxy();
    // Transactional: invalid or duplicate entries leave the old rules intact.
    bool configure(const SecureProxyRule* rules, uint16_t count);
    void clear();
    bool allowTemporaryRoute(uint16_t source, uint16_t destination, uint8_t sourceInterface,
                             uint32_t durationMs);
    bool nonGroupAllowed(uint16_t source, uint16_t destination, uint8_t sourceInterface);
    SecureProxyResult translate(CemiFrame& incoming, CemiFrame& outgoing,
                                uint8_t sourceInterface, uint16_t proxyAddress);
private:
    SecureApplicationLayer& _layer;
    SecureProxyRule _rules[MaxRules];
    uint16_t _count = 0;
    struct Lease { uint16_t source, destination; uint8_t sourceInterface; uint32_t expires; bool active; };
    Lease _leases[4] = {};
};
using SecureProxyDecoder = bool (*)(const uint8_t record[19], SecureProxyRule& rule);
#endif
