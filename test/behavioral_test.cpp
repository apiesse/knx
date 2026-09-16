#include "knx/bau_systemB_device.h"
#include "knx/cemi_frame.h"
#include "knx/dpt.h"
#include <cassert>
#include <cstring>
#include <vector>
#include <cstdlib>

static uint32_t now = 1;
uint32_t millis() { return now; }
void delay(uint32_t ms) { now += ms; }
void delayMicroseconds(unsigned int) {}
void pinMode(uint32_t, uint32_t) {}
void digitalWrite(uint32_t, uint32_t) {}
uint32_t digitalRead(uint32_t) { return 0; }
void attachInterrupt(uint32_t, voidFuncPtr, uint32_t) {}

class FakePlatform : public Platform {
public:
    alignas(4) uint8_t storage[4096] = {};
    void restart() override {}
    void fatalError() override { std::abort(); }
    uint8_t* getNonVolatileMemoryStart() override { return storage; }
    size_t getNonVolatileMemorySize() override { return sizeof(storage); }
};

// InterfaceObject borrows property objects; the fixture releases the dynamically
// constructed defaults after exercising the actual stack, before array teardown.
static void releaseProperties(InterfaceObject &object) {
    std::vector<Property*> properties;
    for (unsigned id = 0; id < 256; ++id) {
        Property *p = object.property(static_cast<PropertyID>(id));
        if (p) properties.push_back(p);
    }
    for (auto *p : properties) delete p;
}

class Link : public DataLinkLayer {
public:
    std::vector<CemiFrame> sent;
    bool reject = false;
    Link(DeviceObject &d, NetworkLayerEntity &n, Platform &p, BusAccessUnit &b) : DataLinkLayer(d,n,p,b) {}
    void loop() override {}
    void enabled(bool) override {}
    bool enabled() const override { return true; }
    DptMedium mediumType() const override { return KNX_TP1; }
    bool sendFrame(CemiFrame &frame) override {
        sent.push_back(frame);
        if (reject) dataConReceived(frame, false);
        return !reject;
    }
    void confirm(size_t index, bool success) { dataConReceived(sent.at(index), success); }
};

class Device : public BauSystemBDevice {
public:
    Link link;
    Device(Platform &p) : BauSystemBDevice(p), link(_deviceObj, _netLayer.getInterface(), p, *this) {
        _netLayer.getInterface().dataLinkLayer(link);
        _memory.readMemory();
    }
    ~Device() {
        releaseProperties(_deviceObj); releaseProperties(_appProgram);
        releaseProperties(_addrTable); releaseProperties(_assocTable); releaseProperties(_groupObjTable);
    }
    bool configured() override { return true; }
    bool enabled() override { return true; }
    void enabled(bool) override {}
    using BauSystemBDevice::sendNextGroupTelegram;
    using BauSystemB::propertyValueReadIndication;
    using BauSystemB::propertyValueExtReadIndication;
    InterfaceObject *getInterfaceObject(uint8_t) override { return &_addrTable; }
    InterfaceObject *getInterfaceObject(ObjectType, uint16_t) override { return &_addrTable; }
    TableObject &table() { return _addrTable; }
    void load(TableObject &table, std::initializer_list<uint16_t> words) {
        const size_t size = words.size() * 2;
        uint8_t *memory = _memory.allocMemory(size);
        assert(memory);
        uint8_t *cursor = memory;
        for (uint16_t word : words) cursor = pushWord(word, cursor);
        std::vector<uint8_t> saved(table.saveSize());
        table.save(saved.data());
        saved[0] = LS_LOADED;
        pushInt(size, saved.data() + 1);
        pushInt(_memory.toRelative(memory), saved.data() + 5);
        table.restore(saved.data());
    }
    void loadGroups() {
        load(_addrTable, {2, 0x1101, 0x1102});
        load(_assocTable, {2, 1, 1, 2, 2});
        load(_groupObjTable, {2, 0xdc08, 0xdc08}); // 2-byte GO, communication/write/read/transmit/update
    }
    void busWrite(uint16_t tsap, float value) {
        CemiFrame frame(3);
        frame.apdu().type(GroupValueWrite);
        GroupObject &go = _groupObjTable.get(tsap);
        uint8_t encoded[2];
        KNX_Encode_Value(KNXValue(value), encoded, 2, DPT_Value_Temp);
        std::memcpy(frame.apdu().data() + 1, encoded, 2);
        _appLayer.dataGroupIndication(NetworkLayerParameter, LowPriority, tsap, frame.apdu());
    }
};

static void memoryTest() {
    FakePlatform p;
    DeviceObject object;
    {
        Memory m(p, object);
        m.readMemory();
        auto *a = m.allocMemory(32), *b = m.allocMemory(32), *c = m.allocMemory(32), *d = m.allocMemory(32);
        assert(a && b && c && d);
        m.freeMemory(a); m.freeMemory(c); m.freeMemory(b);
        auto *abc = m.allocMemory(96);
        auto *tail = m.allocMemory(128);
        assert(abc == a && tail == d + 32);
        m.freeMemory(d); m.freeMemory(abc); m.freeMemory(tail);
        assert(m.allocMemory(4000) == a);
    }
    releaseProperties(object);
}

int main() {
    memoryTest();
    FakePlatform p;
    Device d(p);
    auto &table = d.table();
    uint8_t count = 1;
    uint8_t countBuffer[2] = {0xff,0xff};
    table.readProperty(PID_MCB_TABLE, 0, count, countBuffer);
    assert(count == 1 && countBuffer[0] == 0 && countBuffer[1] == 1);
    uint8_t mcb[8] = {};
    count = 1; table.readProperty(PID_MCB_TABLE, 1, count, mcb); assert(count == 0);
    d.loadGroups();
    // Exercise the actual standard and extended management response workspaces,
    // including their two-byte index-zero allocation and rejected element counts.
    for (uint16_t start : {0,1,2,4095}) for (uint8_t requested : {0,1,2,15,255}) {
        d.propertyValueReadIndication(LowPriority, NetworkLayerParameter, 0x1101,
            SecurityControl{}, 1, PID_MCB_TABLE, requested, start);
        d.propertyValueExtReadIndication(LowPriority, NetworkLayerParameter, 0x1101,
            SecurityControl{}, OT_ADDR_TABLE, 1, PID_MCB_TABLE, requested, start);
    }
    d.link.sent.clear();
    for (uint16_t start : {0,1,2,65535}) for (uint8_t requested : {0,1,2,255}) {
        count = requested;
        table.readProperty(PID_MCB_TABLE, start, count, mcb);
        assert(count == ((requested == 1 && start <= 1) ? 1 : 0));
    }
    count = 1; table.readProperty(PID_MCB_TABLE, 1, count, mcb);
    assert(getInt(mcb) == 6);

    unsigned received = 0, confirmed = 0;
    d.receivedGroupObjectCallback([](GroupObject&, void *p) { ++*static_cast<unsigned*>(p); }, &received);
    d.transmittedGroupObjectCallback([](uint16_t, uint32_t, bool, void *p) { ++*static_cast<unsigned*>(p); }, &confirmed);
    auto &go = d.groupObjectTable().get(1);
    assert(go.value(KNXValue(21.0f), DPT_Value_Temp));
    d.sendNextGroupTelegram();
    assert(d.link.sent.size() == 1 && received == 0);
    const uint32_t first = go.revision();
    assert(go.value(KNXValue(22.0f), DPT_Value_Temp));
    d.sendNextGroupTelegram();
    assert(d.link.sent.size() == 1); // Serialized until the old confirmation arrives.
    d.link.confirm(0, true);
    assert(go.commFlag() == WriteRequest && go.revision() != first);
    d.sendNextGroupTelegram(); d.sendNextGroupTelegram();
    assert(d.link.sent.size() == 2);
    d.busWrite(1, 23.0f);
    assert(received == 1 && (float)go.value(DPT_Value_Temp) == 23.0f);
    d.link.confirm(1, false);
    assert(go.commFlag() == Updated && (float)go.value(DPT_Value_Temp) == 23.0f && confirmed == 2);
    go.value(KNXValue(24.0f), DPT_Value_Temp);
    d.busWrite(1, 25.0f);
    d.sendNextGroupTelegram(); d.sendNextGroupTelegram();
    assert(d.link.sent.size() == 2 && received == 2);
    d.link.reject = true;
    go.value(KNXValue(26.0f), DPT_Value_Temp);
    d.sendNextGroupTelegram(); d.sendNextGroupTelegram();
    assert(go.commFlag() == Error && confirmed == 3);
}
