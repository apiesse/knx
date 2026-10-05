#include "knx/bau_systemB_device.h"
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <map>
#include <vector>

static uint32_t clockNow = 1;
uint32_t millis() { return clockNow; }
void delay(uint32_t ms) { clockNow += ms; }
void delayMicroseconds(unsigned int) {}
void pinMode(uint32_t, uint32_t) {}
void digitalWrite(uint32_t, uint32_t) {}
uint32_t digitalRead(uint32_t) { return 0; }
void attachInterrupt(uint32_t, voidFuncPtr, uint32_t) {}

class TestPlatform : public Platform
{
public:
    alignas(4) uint8_t memory[16384] = {};
    std::map<uint32_t, std::vector<uint8_t>> journal;
    bool healthy = true;
    void restart() override {}
    void fatalError() override { std::abort(); }
    uint8_t* getNonVolatileMemoryStart() override { return memory; }
    size_t getNonVolatileMemorySize() override { return sizeof(memory); }
    bool readFactoryDeviceKey(uint8_t key[16]) override
    { for (unsigned i = 0; i < 16; ++i) key[i] = i; return true; }
    bool fillRandom(uint8_t* bytes, size_t length) override
    { for (size_t i = 0; i < length; ++i) bytes[i] = i + 19; return healthy; }
    int readSecurityState(uint32_t id, uint8_t* bytes, size_t capacity) override
    {
        if (!healthy) return -1;
        auto found = journal.find(id);
        if (found == journal.end()) return 0;
        if (found->second.size() > capacity) return -1;
        memcpy(bytes, found->second.data(), found->second.size());
        return found->second.size();
    }
    bool writeSecurityState(uint32_t id, const uint8_t* bytes, size_t length) override
    {
        if (!healthy) return false;
        journal[id] = std::vector<uint8_t>(bytes, bytes + length); return true;
    }
};

class TestLink : public DataLinkLayer
{
public:
    std::vector<CemiFrame> sent;
    TestLink(DeviceObject& device, NetworkLayerEntity& net, Platform& p, BusAccessUnit& bau)
        : DataLinkLayer(device, net, p, bau) {}
    void loop() override {}
    void enabled(bool) override {}
    bool enabled() const override { return true; }
    DptMedium mediumType() const override { return KNX_TP1; }
    bool sendFrame(CemiFrame& frame) override { sent.push_back(frame); return true; }
    void confirm(size_t index) { dataConReceived(sent.at(index), true); }
};

class TestDevice : public BauSystemBDevice
{
public:
    TestLink link;
    explicit TestDevice(TestPlatform& platform) : BauSystemBDevice(platform),
        link(_deviceObj, _netLayer.getInterface(), platform, *this)
    {
        _netLayer.getInterface().dataLinkLayer(link); _memory.readMemory();
        _deviceObj.individualAddress(0x1102);
        load(_addrTable, {1, 0x2345}); load(_assocTable, {1, 1, 1});
        load(_groupObjTable, {1, 0xdc07}); // one-byte GO, RW/TX/response update
        uint8_t groupKey[18] = {0, 1};
        for (unsigned i = 0; i < 16; ++i) groupKey[i + 2] = i;
        assert(_secIfObj.property(PID_GRP_KEY_TABLE)->write(1, 1, groupKey) == 1);
        uint8_t sender[8] = {0x11, 1};
        assert(_secIfObj.property(PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE)->write(1, 1, sender) == 1);
        uint8_t event = LE_START_LOADING;
        assert(_secIfObj.property(PID_LOAD_STATE_CONTROL)->write(1, 1, &event) == 1);
        event = LE_LOAD_COMPLETED;
        assert(_secIfObj.property(PID_LOAD_STATE_CONTROL)->write(1, 1, &event) == 1);
    }
    ~TestDevice()
    {
        for (auto* object : std::vector<InterfaceObject*>{&_deviceObj, &_appProgram, &_addrTable, &_assocTable, &_groupObjTable})
        {
            std::vector<Property*> owned;
            for (unsigned id = 0; id < 256; ++id)
                if (auto* property = object->property(static_cast<PropertyID>(id)))
                    owned.push_back(property);
            for (auto* property : owned) delete property;
        }
    }
    bool configured() override { return true; }
    bool enabled() override { return true; }
    void enabled(bool) override {}
    InterfaceObject* getInterfaceObject(uint8_t index) override
    { return index == 5 ? static_cast<InterfaceObject*>(&_secIfObj) : &_deviceObj; }
    InterfaceObject* getInterfaceObject(ObjectType type, uint16_t) override
    { return type == OT_SECURITY ? static_cast<InterfaceObject*>(&_secIfObj) : nullptr; }
    SecureApplicationLayer& sal() { return _appLayer; }
    SecurityInterfaceObject& security() { return _secIfObj; }
    GroupObject& go() { return _groupObjTable.get(1); }
    void securityFlag(uint8_t flag)
    { assert(_secIfObj.property(PID_GO_SECURITY_FLAGS)->write(1, 1, &flag) == 1); }
    void load(TableObject& table, std::initializer_list<uint16_t> words)
    {
        const size_t size = words.size() * 2;
        uint8_t* memory = _memory.allocMemory(size); assert(memory);
        uint8_t* cursor = memory; for (uint16_t word : words) cursor = pushWord(word, cursor);
        std::vector<uint8_t> saved(table.saveSize()); table.save(saved.data());
        saved[0] = LS_LOADED; pushInt(size, saved.data() + 1);
        pushInt(_memory.toRelative(memory), saved.data() + 5); table.restore(saved.data());
    }
    using BauSystemBDevice::sendNextGroupTelegram;
};

static std::vector<uint8_t> hex(const char* text)
{
    std::vector<uint8_t> bytes;
    for (; *text; text += 2) { char pair[3] = {text[0], text[1], 0}; bytes.push_back(std::strtoul(pair, nullptr, 16)); }
    return bytes;
}
static CemiFrame wire(const char* text)
{
    const auto bytes = hex(text); CemiFrame frame(bytes.size() - 1);
    memcpy(frame.apdu().data() - 1, bytes.data(), bytes.size());
    frame.sourceAddress(0x1101); frame.destinationAddress(0x2345);
    frame.addressType(GroupAddress); frame.systemBroadcast(Broadcast); return frame;
}

static void knownAnswersAndReplay()
{
    const uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    TestPlatform platform; TestDevice device(platform);
    device.deviceObject().individualAddress(0x1101);
    CemiFrame plain(2), encoded(15);
    plain.apdu().type(GroupValueWrite); plain.apdu().data()[1] = 0xab;
    assert(device.sal().encodeProxyGroupFrame(plain.apdu(), encoded.apdu(), key, 0x1101, 0x2345));
    const auto expected = hex("03f1100000000000017bb1390389df33");
    assert(memcmp(encoded.apdu().data() - 1, expected.data(), expected.size()) == 0);
    device.deviceObject().individualAddress(0x1102);
    CemiFrame recovered(2);
    assert(device.sal().decodeProxyGroupFrame(encoded.apdu(), recovered.apdu(), key));
    assert(recovered.apdu().type() == GroupValueWrite && recovered.apdu().data()[1] == 0xab);
    assert(!device.sal().decodeProxyGroupFrame(encoded.apdu(), recovered.apdu(), key));
    assert(device.security().lastValidSequenceNumber(false, 0x1101) == 1);
    encoded.apdu().data()[7] = 2; // changed sequence cannot pass the MAC
    assert(!device.sal().decodeProxyGroupFrame(encoded.apdu(), recovered.apdu(), key));
    assert(device.security().lastValidSequenceNumber(false, 0x1101) == 1);
}

static void authenticationOnlyUsesInnerApduAndDurableReplay()
{
    TestPlatform platform; TestDevice device(platform); device.securityFlag(1);
    CemiFrame authenticated = wire("03f1000000000000010080abc09c300d");
    device.sal().dataGroupIndication(NetworkLayerParameter, LowPriority, 1, authenticated.apdu());
    assert(device.go().initialized() && device.go().valueRef()[0] == 0xab);
    assert(device.security().lastValidSequenceNumber(false, 0x1101) == 1);
    device.go().valueRef()[0] = 0;
    device.sal().dataGroupIndication(NetworkLayerParameter, LowPriority, 1, authenticated.apdu());
    assert(device.go().valueRef()[0] == 0); // replay must not be delivered
    for (unsigned length = 1; length < 14; ++length)
    {
        CemiFrame truncated(length); truncated.apdu().type(SecureService);
        device.sal().dataGroupIndication(NetworkLayerParameter, LowPriority, 1, truncated.apdu());
    }
    assert(device.go().valueRef()[0] == 0);
}

static void longAuthenticationProtectsEveryByte()
{
    TestPlatform platform; TestDevice device(platform); device.securityFlag(1);
    CemiFrame good = wire("03f1000000000000010080000102030405060708090a0b0c0d0e0fb10ed4bd");
    CemiFrame bad(good);
    bad.apdu().data()[24] ^= 1; // tail outside the first CBC block
    device.sal().dataGroupIndication(NetworkLayerParameter, LowPriority, 1, bad.apdu());
    assert(device.security().lastValidSequenceNumber(false, 0x1101) == 0);
    device.sal().dataGroupIndication(NetworkLayerParameter, LowPriority, 1, good.apdu());
    assert(device.security().lastValidSequenceNumber(false, 0x1101) == 1);
}

static void failureDoesNotWedgeGroupQueue()
{
    TestPlatform platform; TestDevice device(platform); device.securityFlag(3);
    uint8_t reset[2] = {};
    assert(device.security().property(PID_GRP_KEY_TABLE)->write(0, 1, reset) == 1);
    device.go().objectWritten(); device.sendNextGroupTelegram();
    assert(device.link.sent.empty());
    device.securityFlag(0); device.go().objectWritten(); device.sendNextGroupTelegram();
    device.sendNextGroupTelegram(); // scheduler wraps its next-GO cursor
    assert(device.link.sent.size() == 1); // rejected secure send releases _pendingAsap
    device.link.confirm(0);
}

static void synchronizesFullAddressesAndExpiresChallenges()
{
    TestPlatform firstPlatform, secondPlatform;
    TestDevice first(firstPlatform), second(secondPlatform);
    first.deviceObject().individualAddress(0x1201);
    second.deviceObject().individualAddress(0x2302);
    SecurityControl tool; tool.toolAccess = true; tool.dataSecurity = AuthConf;
    assert(first.sal().requestSequenceSync(0x2302, tool));
    assert(first.link.sent.size() == 1 && first.link.sent[0].apdu().length() == 24);
    auto request = first.link.sent[0];
    second.sal().dataIndividualIndication(NetworkLayerParameter, SystemPriority, 0x1201, request.apdu());
    assert(second.link.sent.size() == 1 && second.link.sent[0].apdu().length() == 24);
    auto response = second.link.sent[0];
    first.sal().dataIndividualIndication(NetworkLayerParameter, SystemPriority, 0x2302, response.apdu());
    assert(first.sal().requestSequenceSync(0x2302, tool)); // matching response cleared challenge
    assert(!first.sal().requestSequenceSync(0x2302, tool));
    clockNow += 6001; first.sal().loop();
    assert(first.sal().requestSequenceSync(0x2302, tool));
    firstPlatform.healthy = false; clockNow += 6001; first.sal().loop();
    assert(!first.sal().requestSequenceSync(0x2302, tool));
}

int main()
{
    knownAnswersAndReplay(); authenticationOnlyUsesInnerApduAndDurableReplay();
    longAuthenticationProtectsEveryByte();
    failureDoesNotWedgeGroupQueue(); synchronizesFullAddressesAndExpiresChallenges();
}
