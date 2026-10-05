#include "knx/bau_systemB_coupler.h"
#include "knx/bau_systemB_device.h"
#include "knx/data_property.h"
#ifdef KNX_TUNNELING
#include "knx/knx_ip_frame.h"
#endif
#include <cassert>
#include <cstring>
#include <cstdlib>
#include <map>
#include <vector>

static uint32_t now = 1;
uint32_t millis() { return now; }
void delay(uint32_t milliseconds) { now += milliseconds; }
void delayMicroseconds(unsigned int) {}
void pinMode(uint32_t, uint32_t) {}
void digitalWrite(uint32_t, uint32_t) {}
uint32_t digitalRead(uint32_t) { return 0; }
void attachInterrupt(uint32_t, voidFuncPtr, uint32_t) {}

class TestPlatform : public Platform
{
public:
    alignas(4) uint8_t storage[16384] = {};
    std::map<uint32_t, std::vector<uint8_t>> journal;
    bool failWrites = false;
    bool factoryProvisioned = true;
    unsigned commits = 0;
    std::vector<std::vector<uint8_t>> datagrams;
    bool sendBytesUniCast(uint32_t, uint16_t, uint8_t* bytes, uint16_t length) override
    { datagrams.emplace_back(bytes, bytes + length); return true; }
    void restart() override {}
    void fatalError() override { std::abort(); }
    uint8_t* getNonVolatileMemoryStart() override { return storage; }
    size_t getNonVolatileMemorySize() override { return sizeof(storage); }
    void commitNonVolatileMemory() override { ++commits; }
    bool readFactoryDeviceKey(uint8_t key[16]) override
    { if (!factoryProvisioned) return false; for (unsigned i = 0; i < 16; ++i) key[i] = i + 1; return true; }
    bool fillRandom(uint8_t* bytes, size_t length) override
    { for (size_t i = 0; i < length; ++i) bytes[i] = i + 17; return true; }
    int readSecurityState(uint32_t id, uint8_t* bytes, size_t capacity) override
    {
        const auto found = journal.find(id);
        if (found == journal.end()) return 0;
        if (found->second.size() > capacity) return -1;
        std::memcpy(bytes, found->second.data(), found->second.size());
        return found->second.size();
    }
    bool writeSecurityState(uint32_t id, const uint8_t* bytes, size_t length) override
    {
        if (failWrites) return false;
        journal[id] = std::vector<uint8_t>(bytes, bytes + length); return true;
    }
};

static void releaseProperties(InterfaceObject& object)
{
    std::vector<Property*> properties;
    for (unsigned i = 0; i < 256; ++i)
        if (Property* property = object.property(static_cast<PropertyID>(i)))
            properties.push_back(property);
    for (Property* property : properties) delete property;
}

class TestLink : public DataLinkLayer
{
public:
    std::vector<CemiFrame> sent;
    TestLink(DeviceObject& device, NetworkLayerEntity& network, Platform& platform, BusAccessUnit& bau
#ifdef KNX_TUNNELING
             , IpTunnelServer& tunnel
#endif
             )
        : DataLinkLayer(device, network, platform, bau
#ifdef KNX_TUNNELING
                        , tunnel
#endif
                        ) {}
    void loop() override {}
    void enabled(bool) override {}
    bool enabled() const override { return true; }
    DptMedium mediumType() const override { return KNX_TP1; }
    bool sendFrame(CemiFrame& frame) override { sent.push_back(frame); return true; }
};

class TestDevice : public BauSystemBDevice
{
public:
    InterfaceObject* legacyIp = nullptr;
    InterfaceObject* legacyRouter = nullptr;
#ifdef KNX_TUNNELING
    IpParameterObject ip;
    CemiServer cemi;
    IpTunnelServer tunnel;
#endif
    TestLink link;
    explicit TestDevice(TestPlatform& platform, uint16_t address)
        : BauSystemBDevice(platform)
#ifdef KNX_TUNNELING
          , ip(_deviceObj, platform), cemi(*this, tunnel), tunnel(_deviceObj, ip, platform, cemi)
#endif
          , link(_deviceObj, _netLayer.getInterface(), platform, *this
#ifdef KNX_TUNNELING
                 , tunnel
#endif
                 )
    {
        _netLayer.getInterface().dataLinkLayer(link); _memory.readMemory();
        _deviceObj.individualAddress(address);
#ifdef KNX_TUNNELING
        link.cemiServer(cemi); cemi.dataLinkLayer(link);
#endif
    }
    ~TestDevice()
    {
        releaseProperties(_deviceObj); releaseProperties(_appProgram); releaseProperties(_addrTable);
        releaseProperties(_assocTable); releaseProperties(_groupObjTable);
#ifdef KNX_TUNNELING
        releaseProperties(ip);
#endif
        // SecurityInterfaceObject still scrubs its properties in its destructor.
    }
    bool configured() override { return true; }
    bool enabled() override { return true; }
    void enabled(bool) override {}
    InterfaceObject* getInterfaceObject(uint8_t index) override
    {
        switch (index) {
            case 0: return &_deviceObj; case 1: return &_addrTable; case 2: return &_assocTable;
            case 3: return &_groupObjTable; case 4: return &_appProgram; case 5: return &_secIfObj;
            default: return nullptr;
        }
    }
    InterfaceObject* getInterfaceObject(ObjectType type, uint16_t) override
    {
        switch (type) {
            case OT_DEVICE: return &_deviceObj; case OT_ADDR_TABLE: return &_addrTable;
            case OT_ASSOC_TABLE: return &_assocTable; case OT_GRP_OBJ_TABLE: return &_groupObjTable;
            case OT_APPLICATION_PROG: return &_appProgram; case OT_SECURITY: return &_secIfObj;
            case OT_IP_PARAMETER:
                if (legacyIp) return legacyIp;
#ifdef KNX_TUNNELING
                return &ip;
#else
                return nullptr;
#endif
            case OT_ROUTER: return legacyRouter;
            default: return nullptr;
        }
    }
    SecurityInterfaceObject& security() { return _secIfObj; }
    SecureApplicationLayer& sal() { return _appLayer; }
    size_t systemMetadataCapacity()
    {
        return 6 + LEN_HARDWARE_TYPE + _appProgram.saveSize() + 2 + _deviceObj.saveSize() +
               _groupObjTable.saveSize() + 2 + _addrTable.saveSize() + 2 +
               _assocTable.saveSize() + 2 + _secIfObj.saveSize();
    }
    using BauSystemB::propertyValueWriteIndication;
    using BauSystemB::propertyValueReadIndication;
    using BauSystemB::memoryWriteIndication;
    using BauSystemB::managementMemoryAccessAllowed;
    using BauSystemB::propertyReadAllowed;
    using BauSystemBDevice::groupValueReadAppLayerConfirm;
    using BauSystemBDevice::groupValueWriteIndication;
    void load(TableObject& table, std::initializer_list<uint16_t> words)
    {
        const size_t size = words.size() * 2;
        uint8_t* memory = _memory.allocMemory(size); assert(memory);
        uint8_t* cursor = memory;
        for (uint16_t word : words) cursor = pushWord(word, cursor);
        std::vector<uint8_t> saved(table.saveSize()); table.save(saved.data());
        saved[0] = LS_LOADED; pushInt(size, saved.data() + 1);
        pushInt(_memory.toRelative(memory), saved.data() + 5); table.restore(saved.data());
    }
    void loadGroup()
    {
        load(_addrTable, {1, 0x1101}); load(_assocTable, {1, 1, 1});
        load(_groupObjTable, {1, 0xdc08});
        uint8_t flag = 3; assert(_secIfObj.property(PID_GO_SECURITY_FLAGS)->write(1, 1, &flag) == 1);
    }
};

class TestCoupler : public BauSystemBCoupler
{
public:
    RouterObject router;
#ifdef KNX_TUNNELING
    IpParameterObject ip;
    CemiServer cemi;
    IpTunnelServer tunnel;
#endif
    TestLink primary, secondary;
    explicit TestCoupler(TestPlatform& platform)
        : BauSystemBCoupler(platform), router(_memory)
#ifdef KNX_TUNNELING
          , ip(_deviceObj, platform), cemi(*this, tunnel), tunnel(_deviceObj, ip, platform, cemi)
#endif
          , primary(_deviceObj, _netLayer.getPrimaryInterface(), platform, *this
#ifdef KNX_TUNNELING
                    , tunnel
#endif
                    ),
          secondary(_deviceObj, _netLayer.getSecondaryInterface(), platform, *this
#ifdef KNX_TUNNELING
                    , tunnel
#endif
                    )
    {
        router.initialize1x(KNX_TP1, MAX_APDU_OCTET_COUNT);
        _netLayer.rtObj(router); _netLayer.getPrimaryInterface().dataLinkLayer(primary);
        _netLayer.getSecondaryInterface().dataLinkLayer(secondary);
        _memory.readMemory(); _deviceObj.individualAddress(0x1100);
        const uint8_t route = GROUP_6FFFUNLOCK | GROUP_7000UNLOCK | GROUP_REPEAT;
        router.property(PID_MAIN_LCGRPCONFIG)->write(route);
        router.property(PID_SUB_LCGRPCONFIG)->write(route);
#ifdef KNX_TUNNELING
        primary.cemiServer(cemi); secondary.cemiServer(cemi);
        cemi.dataLinkLayer(secondary); cemi.dataLinkLayerPrimary(primary);
#endif
    }
    ~TestCoupler() {
        releaseProperties(_deviceObj); releaseProperties(_appProgram); releaseProperties(router);
#ifdef KNX_TUNNELING
        releaseProperties(ip);
#endif
    }
    bool enabled() override { return true; }
    void enabled(bool) override {}
    InterfaceObject* getInterfaceObject(uint8_t index) override
    {
        if (index == 0) return &_deviceObj;
        if (index == 1) return &router;
        return index == 2 ? &_secIfObj : nullptr;
    }
    InterfaceObject* getInterfaceObject(ObjectType type, uint16_t) override
    {
        if (type == OT_SECURITY) return &_secIfObj;
        if (type == OT_DEVICE) return &_deviceObj;
#ifdef KNX_TUNNELING
        if (type == OT_IP_PARAMETER) return &ip;
#endif
        return type == OT_ROUTER ? &router : nullptr;
    }
    SecurityInterfaceObject& security() { return _secIfObj; }
    void receive(CemiFrame frame, uint8_t interface)
    {
        auto& entity = interface == 0 ? _netLayer.getPrimaryInterface() : _netLayer.getSecondaryInterface();
        entity.dataIndication(AckRequested, frame.addressType(), frame.destinationAddress(),
                              frame.frameType(), frame.npdu(), frame.priority(), frame.sourceAddress());
    }
};

static void sender(SecurityInterfaceObject& security, uint16_t address)
{
    uint8_t entry[8] = {}; pushWord(address, entry);
    assert(security.property(PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE)->write(1, 1, entry) == 1);
}

static CemiFrame plain(uint16_t source, uint16_t destination = 0x1101, ApduType service = GroupValueWrite)
{
    CemiFrame frame(1); frame.apdu().type(service); frame.apdu().data()[0] |= 1;
    frame.sourceAddress(source); frame.destinationAddress(destination); frame.addressType(GroupAddress);
    frame.hopCount(4); frame.priority(LowPriority); frame.tpdu().type(DataGroup);
    return frame;
}

static SecureProxyRule testRule()
{
    SecureProxyRule rule; rule.groupAddress = 0x1101; rule.primarySecure = true;
    rule.primaryToSecondary = true; rule.secondaryToPrimary = true;
    for (unsigned i = 0; i < 16; ++i) rule.key[i] = 0xa0 + i;
    return rule;
}

// Explicit fixture codec only. It is intentionally not an AN192 decoder.
static bool fixtureDecoder(const uint8_t record[19], SecureProxyRule& rule)
{ if (record[0] != 0x42) return false; rule = testRule(); return true; }

static void managementAndResponseTest()
{
    TestPlatform platform; TestDevice device(platform, 0x1101);
    uint8_t mode[3] = {0, 0, 1}, result[8] = {}; uint8_t length = sizeof(result);
    device.security().command(PID_SECURITY_MODE, mode, sizeof(mode), result, length);
    assert(device.security().isSecurityModeEnabled());
    device.deviceObject().progMode(true);
#ifdef KNX_TUNNELING
    // A secure IP carrier does not elevate cEMI v1's anonymous identity. Even
    // an open programming window cannot force an M_Reset EEPROM commit.
    uint8_t reset[1] = {M_Reset_req}; CemiFrame resetFrame(reset, sizeof(reset));
    device.cemi.frameReceived(resetFrame, 1); assert(platform.commits == 0);
#endif
    SecurityControl insecure{}, authOnly{true, Auth}, runtime{false, AuthConf}, tool{true, AuthConf};
    uint8_t value = 1;
    for (auto control : {insecure, authOnly, runtime})
    {
        device.propertyValueWriteIndication(LowPriority, NetworkLayerParameter, 0x2201, control,
                                            0, PID_DEVICE_CONTROL, 1, 1, &value, 1);
        assert(device.deviceObject().propertyData(PID_DEVICE_CONTROL)[0] == 0);
        assert(!device.managementMemoryAccessAllowed(control));
    }
    device.deviceObject().progMode(false);
    device.propertyValueWriteIndication(LowPriority, NetworkLayerParameter, 0x2201, tool,
                                        0, PID_DEVICE_CONTROL, 1, 1, &value, 1);
    assert(device.deviceObject().propertyData(PID_DEVICE_CONTROL)[0] == 1);
    assert(device.managementMemoryAccessAllowed(tool));
    assert(!device.propertyReadAllowed(device.security().property(PID_TOOL_KEY), tool));
    // Secret property read produces an empty response even in programming mode.
    device.deviceObject().progMode(true); device.link.sent.clear();
    device.propertyValueReadIndication(LowPriority, NetworkLayerParameter, 0x2201, insecure,
                                       5, PID_TOOL_KEY, 1, 1);
    assert(!device.link.sent.empty());
    assert(device.link.sent.back().apdu().length() < 16);
    device.loadGroup();
    auto& group = device.groupObjectTable().get(1);
    uint8_t response[2] = {0x12, 0x34};
    for (auto control : {insecure, authOnly, tool})
    {
        device.groupValueReadAppLayerConfirm(1, LowPriority, NetworkLayerParameter, control, response, 2);
        assert(group.valueRef()[0] == 0 && group.valueRef()[1] == 0);
    }
    device.groupValueReadAppLayerConfirm(1, LowPriority, NetworkLayerParameter, runtime, response, 2);
    assert(group.valueRef()[0] == 0x12 && group.valueRef()[1] == 0x34);
    uint8_t changed[2] = {0x56, 0x78};
    device.groupValueWriteIndication(1, LowPriority, NetworkLayerParameter, insecure, changed, 2);
    assert(group.valueRef()[0] == 0x12);
}

static void secureCapablePlainCompatibilityTest()
{
    TestPlatform platform;
    TestDevice device(platform, 0x1101);
    device.loadGroup();
    const uint8_t plainFlag = 0;
    assert(device.security().property(PID_GO_SECURITY_FLAGS)->write(1, 1, &plainFlag) == 1);
    assert(device.security().getGroupObjectSecurity(1) == None);
    auto& group = device.groupObjectTable().get(1);
    for (uint8_t secureMode : { uint8_t(0), uint8_t(1) })
    {
        uint8_t mode[3] = {0, 0, secureMode}, result[8] = {};
        uint8_t length = sizeof(result);
        device.security().command(PID_SECURITY_MODE, mode, sizeof(mode), result, length);
        assert(device.security().isSecurityModeEnabled() == bool(secureMode));
        // Real SAL -> association table -> BAU -> GO path. Plain GA security is
        // independent from whether authenticated commissioning is enabled.
        CemiFrame incoming(3);
        incoming.sourceAddress(0x2201); incoming.destinationAddress(0x1101);
        incoming.addressType(GroupAddress); incoming.apdu().type(GroupValueWrite);
        incoming.apdu().data()[1] = 0x12 + secureMode;
        incoming.apdu().data()[2] = 0x34;
        device.sal().dataGroupIndication(NetworkLayerParameter, LowPriority, 1, incoming.apdu());
        assert(group.valueRef()[0] == 0x12 + secureMode && group.valueRef()[1] == 0x34);
        incoming.apdu().type(GroupValueResponse);
        incoming.apdu().data()[1] = 0x56;
        device.sal().dataGroupIndication(NetworkLayerParameter, LowPriority, 1, incoming.apdu());
        assert(group.valueRef()[0] == 0x56 && group.valueRef()[1] == 0x34);
        uint8_t value[2] = {0x78, 0x9a};
        device.link.sent.clear();
        device.sal().groupValueWriteRequest(AckRequested, 1, LowPriority,
                                            NetworkLayerParameter, SecurityControl{}, value, sizeof(value));
        assert(!device.link.sent.empty());
        assert(device.link.sent.back().apdu().type() == GroupValueWrite);
        assert(device.link.sent.back().apdu().data()[1] == 0x78);
        // Runtime secure/tool identities cannot silently update a plain object.
        uint8_t forbidden[2] = {0xa5, 0x5a};
        for (auto control : {SecurityControl{false, AuthConf}, SecurityControl{true, AuthConf}})
        {
            const uint8_t oldValue[2] = {group.valueRef()[0], group.valueRef()[1]};
            device.groupValueWriteIndication(1, LowPriority, NetworkLayerParameter, control, forbidden, sizeof(forbidden));
            assert(std::memcmp(group.valueRef(), oldValue, sizeof(oldValue)) == 0);
        }
    }
}

static void legacyPropertyAbsenceTest()
{
#ifndef USE_IPSECURE
    TestPlatform platform;
    platform.factoryProvisioned = false;
    TestDevice device(platform, 0x1101);
    InterfaceObject legacyIp, legacyRouter;
    device.legacyIp = &legacyIp;
    device.legacyRouter = &legacyRouter;
    assert(!device.security().isFactoryProvisioned());
    assert(!device.security().isLoaded());
    assert(legacyIp.property(PID_BACKBONE_KEY) == nullptr);
    assert(legacyRouter.property(PID_SECURITY_PROXY_GRP_KEY_TABLE) == nullptr);
    device.deviceObject().progMode(false);
    assert(!device.managementMemoryAccessAllowed());
    device.deviceObject().progMode(true);
    assert(device.managementMemoryAccessAllowed());
#endif
}

static void roomUnitCapacityTest()
{
    TestPlatform platform;
    TestDevice device(platform, 0x1101);
    // Derive the RoomUnit profile from the real property saveSize() capacities.
    // Host fixtures may use wider defaults; only the four profile-dependent
    // tables change. Do not modify library defaults or the generated profile.
    const long profileAdjustment =
        20L * (32L - KNX_SECURE_P2P_KEYS) +
        18L * (128L - KNX_SECURE_GROUP_KEYS) +
        8L * (128L - KNX_SECURE_SENDERS) +
        (126L - KNX_SECURE_GROUP_OBJECTS);
    const long sioBytes = device.security().saveSize() + profileAdjustment;
    const long metadataBytes = device.systemMetadataCapacity() + profileAdjustment;
    assert(sioBytes == 4168);
    assert(metadataBytes == 4252);
    const auto align4 = [](size_t size) { return (size + 3) & ~size_t(3); };
    // All 126 GOs linked to one distinct GA each, 96 parameter bytes, and full
    // SIO key/sender capacities. Extra associations consume the remaining pool.
    const size_t total = align4(metadataBytes) + align4(96) +
                         align4(2 + 126 * 2) + align4(2 + 126 * 4) + align4(2 + 126 * 2);
    assert(total == 5368);
    assert(8192 - total == 2824);
}

static void proxyRoutingTest()
{
    TestPlatform platform, remotePlatform, receiverPlatform;
    TestCoupler coupler(platform); TestDevice remote(remotePlatform, 0x2201);
    TestDevice receiver(receiverPlatform, 0x3301);
    auto rule = testRule(); assert(coupler.configureSecureProxy(&rule, 1));
    sender(coupler.security(), 0x2201); sender(receiver.security(), 0x1100);
    coupler.receive(plain(0x1102), 1);
    assert(coupler.primary.sent.size() == 1);
    CemiFrame secured = coupler.primary.sent.back();
    assert(secured.sourceAddress() == 0x1100 && secured.hopCount() == 3);
    assert(secured.apdu().type() == SecureService);
    CemiFrame decoded(1);
    assert(receiver.sal().decodeProxyGroupFrame(secured.apdu(), decoded.apdu(), rule.key));
    assert(decoded.apdu().type() == GroupValueWrite && (decoded.apdu().data()[0] & 0x3f) == 1);
    CemiFrame message = plain(0x2201), remoteSecure(14);
    assert(remote.sal().encodeProxyGroupFrame(message.apdu(), remoteSecure.apdu(), rule.key, 0x2201, 0x1101));
    remoteSecure.hopCount(4);
    coupler.receive(remoteSecure, 0);
    assert(coupler.secondary.sent.size() == 1);
    assert(coupler.secondary.sent.back().apdu().type() == GroupValueWrite);
    assert(coupler.secondary.sent.back().sourceAddress() == 0x1100);
    coupler.receive(remoteSecure, 0); // replay rejected through the actual network path
    assert(coupler.secondary.sent.size() == 1);
    coupler.receive(plain(0x2201), 0); // unsecured frame on protected side
    assert(coupler.secondary.sent.size() == 1);
    CemiFrame altered(remoteSecure); altered.apdu().data()[altered.apdu().length() - 1] ^= 1;
    coupler.receive(altered, 0); assert(coupler.secondary.sent.size() == 1);
    auto unsupported = plain(0x1102, 0x1101, DeviceDescriptorRead);
    coupler.receive(unsupported, 1); assert(coupler.primary.sent.size() == 1);
    auto huge = CemiFrame(242); huge.apdu().type(GroupValueWrite); huge.addressType(GroupAddress);
    huge.sourceAddress(0x1102); huge.destinationAddress(0x1101); huge.hopCount(4);
    coupler.receive(huge, 1); assert(coupler.primary.sent.size() == 1);
    coupler.receive(plain(0x1102, 0x1201), 1); // unrelated group is not implicitly decrypted/encrypted
    assert(coupler.primary.sent.size() == 2 && coupler.primary.sent.back().sourceAddress() == 0x1102);
    auto oneWay = rule; oneWay.secondaryToPrimary = false;
    assert(coupler.configureSecureProxy(&oneWay, 1)); coupler.receive(plain(0x1102), 1);
    assert(coupler.primary.sent.size() == 2);
    assert(coupler.configureSecureProxy(&rule, 1));
    // A lease is limited to exactly one IA pair/direction and expires on elapsed time.
    auto individual = plain(0x2201); individual.addressType(IndividualAddress); individual.tpdu().type(DataInduvidual);
    coupler.receive(individual, 0); assert(coupler.secondary.sent.size() == 1);
    assert(coupler.allowTemporaryRoute(0x2201, 0x1101, 0, 50));
    coupler.receive(individual, 0); assert(coupler.secondary.sent.size() == 2);
    now += 51; coupler.receive(individual, 0); assert(coupler.secondary.sent.size() == 2);
    // Opaque ETS records must never activate a guessed decoder or plaintext fallback.
    uint8_t opaque[19] = {0x42}; coupler.router.property(PID_SECURITY_PROXY_GRP_KEY_TABLE)->write(1, 1, opaque);
    coupler.receive(plain(0x1102), 1); assert(coupler.primary.sent.size() == 2);
    std::vector<uint8_t> saved(coupler.router.saveSize()); coupler.router.save(saved.data());
    saved[0] = LS_LOADED; coupler.router.restore(saved.data());
    coupler.securityProxyDecoder(fixtureDecoder);
    coupler.receive(plain(0x1102), 1); assert(coupler.primary.sent.size() == 3);
}

static void proxyDurabilityTest()
{
    TestPlatform platform, remotePlatform;
    TestDevice remote(remotePlatform, 0x2201);
    auto rule = testRule(); CemiFrame message = plain(0x2201), secured(14);
    assert(remote.sal().encodeProxyGroupFrame(message.apdu(), secured.apdu(), rule.key, 0x2201, 0x1101));
    secured.hopCount(4);
    {
        TestCoupler coupler(platform); assert(coupler.configureSecureProxy(&rule, 1));
        sender(coupler.security(), 0x2201);
        CemiFrame altered(secured); altered.apdu().data()[altered.apdu().length() - 1] ^= 1;
        coupler.receive(altered, 0); assert(coupler.secondary.sent.empty());
        // MAC failure must not consume replay state; durable commit failure
        // must likewise withhold application delivery.
        platform.failWrites = true;
        coupler.receive(secured, 0); assert(coupler.secondary.sent.empty());
        platform.failWrites = false;
        coupler.receive(secured, 0); assert(coupler.secondary.sent.size() == 1);
    }
    {
        TestCoupler rebooted(platform); assert(rebooted.configureSecureProxy(&rule, 1));
        sender(rebooted.security(), 0x2201);
        rebooted.receive(secured, 0); assert(rebooted.secondary.sent.empty());
        // A fresh sender frame works after reboot, while the committed one
        // above remains a replay despite the ETS IA table's initial counter.
        CemiFrame next(14);
        assert(remote.sal().encodeProxyGroupFrame(message.apdu(), next.apdu(), rule.key, 0x2201, 0x1101));
        next.hopCount(4); rebooted.receive(next, 0);
        assert(rebooted.secondary.sent.size() == 1);
        platform.failWrites = true;
        rebooted.receive(plain(0x1102), 1); assert(rebooted.primary.sent.empty());
        platform.failWrites = false;
        auto stopped = plain(0x1102); stopped.hopCount(0);
        rebooted.receive(stopped, 1); assert(rebooted.primary.sent.empty());
        auto unlimited = plain(0x1102); unlimited.hopCount(7);
        rebooted.receive(unlimited, 1); assert(rebooted.primary.sent.size() == 1);
        assert(rebooted.primary.sent.back().hopCount() == 6);
    }
}

static void propertyStorageRegressionTest()
{
    DataProperty table(PID_SECURITY_PROXY_GRP_KEY_TABLE, true, PDT_GENERIC_19, 3, ReadLv0 | WriteLv0);
    uint8_t first[19], third[19], bytes[19] = {};
    std::memset(first, 0xa5, sizeof(first)); std::memset(third, 0x5a, sizeof(third));
    assert(table.write(1, 1, first) == 1);
    assert(table.write(3, 1, third) == 1); // growth keeps old entries and zeroes holes
    assert(table.read(1, 1, bytes) == 1 && std::memcmp(first, bytes, 19) == 0);
    assert(table.read(2, 1, bytes) == 1);
    for (uint8_t byte : bytes) assert(byte == 0);
    std::vector<uint8_t> saved(table.saveSize()); table.save(saved.data());
    assert(getWord(saved.data()) == 3 && std::memcmp(saved.data() + 2, first, 19) == 0);
    uint8_t reset[2] = {}; assert(table.write(0, 1, reset) == 1 && table.data() == nullptr);
    table.restore(saved.data());
    assert(table.read(3, 1, bytes) == 1 && std::memcmp(third, bytes, 19) == 0);
    DataProperty one(PID_SECURITY_PROXY_GRP_KEY_TABLE, true, PDT_GENERIC_19, 3, ReadLv0 | WriteLv0);
    assert(one.write(1, 1, first) == 1);
    std::vector<uint8_t> shorter(one.saveSize()); one.save(shorter.data());
    table.restore(shorter.data()); // replacement of a differently sized old array
    assert(table.read(1, 1, bytes) == 1 && std::memcmp(first, bytes, 19) == 0);
    assert(table.read(2, 1, bytes) == 0);
}

static void proxyFactoryResetTest()
{
    TestPlatform platform;
    TestCoupler coupler(platform);
    Property* keys = coupler.router.property(PID_SECURITY_PROXY_GRP_KEY_TABLE);
    uint8_t record[19];
    std::memset(record, 0xa5, sizeof(record));
    assert(keys->write(1, 1, record) == 1);
    std::vector<uint8_t> loaded(coupler.router.saveSize());
    coupler.router.save(loaded.data());
    loaded[0] = LS_LOADED;
    coupler.router.restore(loaded.data());
    coupler.router.masterReset(ConfirmedRestart, 0);
    assert(coupler.router.loadState() == LS_LOADED);
    assert(keys->read(1, 1, record) == 1 && record[0] == 0xa5);
    coupler.router.masterReset(ResetIA, 0);
    assert(keys->read(1, 1, record) == 1 && record[0] == 0xa5);

    for (EraseCode code : { FactoryReset, FactoryResetWithoutIA })
    {
        std::memset(record, 0xa5, sizeof(record));
        assert(keys->write(1, 1, record) == 1);
        coupler.router.masterReset(code, 0);
        assert(coupler.router.loadState() == LS_UNLOADED);
        assert(coupler.router.secureProxyEntryCount() == keys->MaxElements());
        for (uint16_t index = 1; index <= keys->MaxElements(); ++index)
        {
            assert(keys->read(index, 1, record) == 1);
            for (uint8_t byte : record) assert(byte == 0);
        }
        std::vector<uint8_t> saved(keys->saveSize(), 0xff);
        uint8_t* end = keys->save(saved.data());
        assert(end == saved.data() + saved.size());
        assert(getWord(saved.data()) == keys->MaxElements());
        for (size_t i = 2; i < saved.size(); ++i) assert(saved[i] == 0);
        SecureProxyRule rule;
        assert(!coupler.router.readSecureProxyRule(fixtureDecoder, 1, rule));
    }
}

#ifdef KNX_TUNNELING
static std::vector<uint8_t> localTransport(APDU& apdu, bool connected)
{
    std::vector<uint8_t> bytes(apdu.length() + 10, 0);
    bytes[0] = connected ? T_data_connected_req : T_data_individual_req;
    bytes[8] = apdu.length();
    std::memcpy(bytes.data() + 9, apdu.data() - 1, apdu.length() + 1);
    return bytes;
}

static void cemiLocalTransportTest()
{
    TestPlatform platform; TestDevice device(platform, 0x1101);
    uint8_t mode[3] = {0, 0, 1}, result[8] = {}; uint8_t length = sizeof(result);
    device.security().command(PID_SECURITY_MODE, mode, sizeof(mode), result, length);
    auto* channel = device.tunnel.tunnelConnections() + KNX_TUNNELING;
    channel->ChannelId = 5; channel->IsConfig = true;
    channel->IpAddress = 0x7f000001; channel->PortCtrl = channel->PortData = 3671;
    // The cEMI TL envelope has neither addresses nor bus control fields.
    CemiFrame request(6); request.apdu().type(PropertyValueWrite);
    uint8_t* data = request.apdu().data();
    data[1] = 0; data[2] = PID_DEVICE_CONTROL; data[3] = 0x10; data[4] = 1; data[5] = 1;
    device.deviceObject().progMode(true);
    for (bool connected : {false, true})
    {
        auto bytes = localTransport(request.apdu(), connected);
        assert(CemiFrame::validBuffer(bytes.data(), bytes.size()));
        CemiFrame frame(bytes.data(), bytes.size());
        platform.datagrams.clear(); device.cemi.frameReceived(frame, 5);
        assert(device.deviceObject().propertyData(PID_DEVICE_CONTROL)[0] == 0);
        assert(device.link.sent.empty());
        assert(platform.datagrams.size() == 1);
        const auto& response = platform.datagrams.back();
        assert(getWord(response.data() + 2) == DeviceConfigurationRequest);
        assert(response[10] == (connected ? T_data_connected_ind : T_data_individual_ind));
        assert(CemiFrame::validBuffer(response.data() + 10, response.size() - 10));
        for (unsigned i = 12; i < 18; ++i) assert(response[i] == 0);
        assert((response[19] & 0xfc) == 0);
    }
    auto bytes = localTransport(request.apdu(), false);
    CemiFrame unbound(bytes.data(), bytes.size());
    platform.datagrams.clear(); device.cemi.frameReceived(unbound, 6);
    assert(platform.datagrams.empty()); // not a live device-management channel
    // Provisional SAL-local framing must not enable a guessed secure mode.
    // This OpenSSL Tool AuthConf candidate under the unverified zero-IA nonce
    // hypothesis is rejected without delivery/response (not a normative KAT).
    CemiFrame secure(19); secure.apdu().type(SecureService);
    const uint8_t secureData[18] = {0x90, 0, 0, 0, 0, 0, 1,
                                  0xac, 0x19, 0xe1, 0x0c, 0xc2, 0x0c, 0x88,
                                  0xbb, 0xc1, 0x3c, 0x4f};
    std::memcpy(secure.apdu().data() + 1, secureData, sizeof(secureData));
    auto protectedBytes = localTransport(secure.apdu(), false);
    CemiFrame protectedFrame(protectedBytes.data(), protectedBytes.size());
    device.cemi.frameReceived(protectedFrame, 5);
    assert(platform.datagrams.empty() && device.link.sent.empty());
    // Every length-derived offset and every reserved/TPCI bit fails closed.
    for (size_t i = 0; i < bytes.size(); ++i)
        assert(!CemiFrame::validBuffer(bytes.data(), i));
    auto invalid = bytes; invalid[2] = 1;
    assert(!CemiFrame::validBuffer(invalid.data(), invalid.size()));
    invalid = bytes; invalid[9] |= 0x40;
    assert(!CemiFrame::validBuffer(invalid.data(), invalid.size()));
    invalid = bytes; ++invalid[8];
    assert(!CemiFrame::validBuffer(invalid.data(), invalid.size()));
    // M_FuncProp is anonymous and cannot turn a secure configuration off.
    uint8_t function[8] = {M_FuncPropCommand_req, 0, OT_SECURITY, 1, PID_SECURITY_MODE, 0, 0, 0};
    CemiFrame command(function, sizeof(function));
    device.cemi.frameReceived(command, 5);
    assert(device.security().isSecurityModeEnabled());
    assert(platform.datagrams.back().back() == ReturnCodes::AccessDenied);
}
#endif

int main()
{
    managementAndResponseTest(); secureCapablePlainCompatibilityTest();
    legacyPropertyAbsenceTest();
    roomUnitCapacityTest();
    proxyRoutingTest(); proxyDurabilityTest();
    propertyStorageRegressionTest();
    proxyFactoryResetTest();
#ifdef KNX_TUNNELING
    cemiLocalTransportTest();
#endif
}
