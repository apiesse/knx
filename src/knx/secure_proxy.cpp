#include "secure_proxy.h"
#ifdef USE_DATASECURE
#include "secure_application_layer.h"
#include <cstring>

SecureProxy::~SecureProxy() { clear(); }

void SecureProxy::clear()
{
    volatile uint8_t* bytes = reinterpret_cast<volatile uint8_t*>(_rules);
    for (size_t i = 0; i < sizeof(_rules); ++i) bytes[i] = 0;
    _count = 0;
    std::memset(_leases, 0, sizeof(_leases));
}

bool SecureProxy::configure(const SecureProxyRule* rules, uint16_t count)
{
    if (count > MaxRules || (count && !rules)) return false;
    for (uint16_t i = 0; i < count; ++i)
    {
        const auto& rule = rules[i];
        // Broadcast/unicast translation and a secure-side-only passthrough are
        // outside this proxy profile. A group must cross one trust boundary.
        if (!rule.groupAddress || rule.primarySecure == rule.secondarySecure ||
            (!rule.primaryToSecondary && !rule.secondaryToPrimary)) return false;
        for (uint16_t j = 0; j < i; ++j)
            if (rules[j].groupAddress == rule.groupAddress) return false;
    }
    bool unchanged = count == _count;
    for (uint16_t i = 0; unchanged && i < count; ++i)
    {
        const auto& a = rules[i]; const auto& b = _rules[i];
        unchanged = a.groupAddress == b.groupAddress && a.primarySecure == b.primarySecure &&
            a.secondarySecure == b.secondarySecure && a.primaryToSecondary == b.primaryToSecondary &&
            a.secondaryToPrimary == b.secondaryToPrimary && std::memcmp(a.key, b.key, 16) == 0;
    }
    if (unchanged) return true;
    clear();
    if (count) std::memcpy(_rules, rules, sizeof(SecureProxyRule) * count);
    _count = count;
    return true;
}

static bool runtimeGroupService(APDU& apdu)
{
    const ApduType service = apdu.type();
    return service == GroupValueRead || service == GroupValueWrite || service == GroupValueResponse;
}

SecureProxyResult SecureProxy::translate(CemiFrame& incoming, CemiFrame& outgoing,
                                       uint8_t sourceInterface, uint16_t proxyAddress)
{
    if (sourceInterface > 1 || !incoming.valid()) return SecureProxyResult::Drop;
    if (incoming.addressType() != GroupAddress || !incoming.destinationAddress())
        return SecureProxyResult::ForwardUnchanged;
    const SecureProxyRule* match = nullptr;
    for (uint16_t i = 0; i < _count; ++i)
        if (_rules[i].groupAddress == incoming.destinationAddress()) { match = &_rules[i]; break; }
    if (!match) return SecureProxyResult::ForwardUnchanged;
    if (incoming.tpdu().control() || incoming.tpdu().numbered()) return SecureProxyResult::Drop;
    if (!proxyAddress || !incoming.sourceAddress() || proxyAddress == incoming.sourceAddress())
        return SecureProxyResult::Drop;
    if ((sourceInterface == 0 && !match->primaryToSecondary) ||
        (sourceInterface == 1 && !match->secondaryToPrimary)) return SecureProxyResult::Drop;
    const bool secureInput = sourceInterface == 0 ? match->primarySecure : match->secondarySecure;
    const uint16_t inputLength = incoming.apdu().length();
    if (secureInput)
    {
        if (incoming.apdu().type() != SecureService || inputLength < 14) return SecureProxyResult::Drop;
        CemiFrame plain(inputLength - 13);
        if (!_layer.decodeProxyGroupFrame(incoming.apdu(), plain.apdu(), match->key) ||
            !runtimeGroupService(plain.apdu())) return SecureProxyResult::Drop;
        outgoing = plain;
    }
    else
    {
        if (!runtimeGroupService(incoming.apdu()) || inputLength > MAX_APDU_OCTET_COUNT - 13)
            return SecureProxyResult::Drop;
        CemiFrame secured(inputLength + 13);
        if (!_layer.encodeProxyGroupFrame(incoming.apdu(), secured.apdu(), match->key,
                                          proxyAddress, incoming.destinationAddress()))
            return SecureProxyResult::Drop;
        outgoing = secured;
    }
    // A translation originates at this coupler. In particular it must never
    // encrypt with another sender's IA while using our own sequence counter.
    outgoing.sourceAddress(proxyAddress);
    outgoing.destinationAddress(incoming.destinationAddress());
    outgoing.addressType(GroupAddress);
    outgoing.hopCount(incoming.hopCount());
    outgoing.priority(incoming.priority());
    outgoing.systemBroadcast(Broadcast);
    outgoing.repetition(incoming.repetition());
    return SecureProxyResult::Translated;
}

bool SecureProxy::allowTemporaryRoute(uint16_t source, uint16_t destination, uint8_t sourceInterface,
                                     uint32_t durationMs)
{
    if (!source || sourceInterface > 1 || !durationMs || durationMs > 60000) return false;
    const uint32_t now = millis();
    for (auto& lease : _leases)
    {
        if (lease.active && static_cast<int32_t>(now - lease.expires) >= 0) lease.active = false;
        if (!lease.active || (lease.source == source && lease.destination == destination &&
                              lease.sourceInterface == sourceInterface))
        {
            lease = {source, destination, sourceInterface, now + durationMs, true};
            return true;
        }
    }
    return false;
}

bool SecureProxy::nonGroupAllowed(uint16_t source, uint16_t destination, uint8_t sourceInterface)
{
    if (sourceInterface > 1) return false;
    if (_count == 0) return true; // No proxy boundary has been configured.
    const uint32_t now = millis();
    for (auto& lease : _leases)
    {
        if (lease.active && static_cast<int32_t>(now - lease.expires) >= 0) lease.active = false;
        if (lease.active && lease.source == source && lease.destination == destination &&
            lease.sourceInterface == sourceInterface) return true;
    }
    return false;
}
#endif
