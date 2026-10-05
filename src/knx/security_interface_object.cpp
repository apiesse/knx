#include "config.h"
#ifdef USE_DATASECURE

#include <cstring>
#include "security_interface_object.h"
#include "secure_application_layer.h"
#include "bits.h"
#include "data_property.h"
#include "callback_property.h"
#include "function_property.h"

namespace
{
constexpr uint64_t kMaximumSequence = UINT64_C(0xffffffffffff);
static_assert(KNX_SECURE_SEQUENCE_RESERVATION > 0, "Secure sequence reservation must be positive");
static_assert(KNX_SECURE_SENDERS > 0 && KNX_SECURE_TOOL_SENDERS > 0,
              "Secure replay caches must have positive capacity");
static_assert(KNX_SECURE_FAILURE_LOG_SIZE > 0 && KNX_SECURE_FAILURE_LOG_SIZE <= 255,
              "Secure failure log must have 1..255 entries");
void clearSecret(uint8_t* data, size_t length)
{
    volatile uint8_t* target = data;
    while (length--)
        *target++ = 0;
}
}

SecurityInterfaceObject::SecurityInterfaceObject()
{
    Property* properties[] =
    {
        new DataProperty( PID_OBJECT_TYPE, false, PDT_UNSIGNED_INT, 1, ReadLv3 | WriteLv0, (uint16_t)OT_SECURITY ),
        new CallbackProperty<SecurityInterfaceObject>(this, PID_LOAD_STATE_CONTROL, true, PDT_CONTROL, 1, ReadLv3 | WriteLv3,
            // ReadCallback of PID_LOAD_STATE_CONTROL
            [](SecurityInterfaceObject* obj, uint16_t start, uint8_t count, uint8_t* data) -> uint8_t {
                if (!data || count != 1 || start > 1)
                    return 0;
                if (start == 0)
                {
                    pushWord(1, data);
                    return 1;
                }

                data[0] = obj->_state;
                return 1;
            },
            // WriteCallback of PID_LOAD_STATE_CONTROL
            [](SecurityInterfaceObject* obj, uint16_t start, uint8_t count, const uint8_t* data) -> uint8_t {
                if (!data || start != 1 || count != 1)
                    return 0;
                obj->loadEvent(data);
                return 1;
            }),
        new FunctionProperty<SecurityInterfaceObject>(this, PID_SECURITY_MODE,
            // Command Callback of PID_SECURITY_MODE
            [](SecurityInterfaceObject* obj, uint8_t* data, uint8_t length, uint8_t* resultData, uint8_t& resultLength) -> void {
                if (!resultData || resultLength < 2)
                {
                    resultLength = 0;
                    return;
                }
                if (data == nullptr || length != 3)
                {
                    resultData[0] = ReturnCodes::DataVoid;
                    resultLength = 1;
                    return;
                }
                uint8_t serviceId = data[1] & 0xff;
                if (serviceId != 0)
                {
                    resultData[0] = ReturnCodes::InvalidCommand;
                    resultLength = 1;
                    return;
                }
                uint8_t mode = data[2];
                if (mode > 1)
                {
                    resultData[0] = ReturnCodes::DataVoid;
                    resultLength = 1;
                    return;
                }
                obj->setSecurityMode(mode == 1);
                resultData[0] = ReturnCodes::Success;
                resultData[1] = serviceId;
                resultLength = 2;
            },
            // State Callback of PID_SECURITY_MODE
            [](SecurityInterfaceObject* obj, uint8_t* data, uint8_t length, uint8_t* resultData, uint8_t& resultLength) -> void {
                if (!resultData || resultLength < 3)
                {
                    resultLength = 0;
                    return;
                }
                if (data == nullptr || length != 2)
                {
                    resultData[0] = ReturnCodes::DataVoid;
                    resultLength = 1;
                    return;
                }
                uint8_t serviceId = data[1] & 0xff;
                if (serviceId != 0)
                {
                    resultData[0] = ReturnCodes::InvalidCommand;
                    resultLength = 1;
                    return;
                }
                resultData[0] = ReturnCodes::Success;
                resultData[1] = serviceId;
                resultData[2] = obj->isSecurityModeEnabled() ? 1 : 0;
                resultLength = 3;
            }),
        new DataProperty( PID_P2P_KEY_TABLE, true, PDT_GENERIC_20, KNX_SECURE_P2P_KEYS, ReadLv0 | WriteLv0 ),
        new DataProperty( PID_GRP_KEY_TABLE, true, PDT_GENERIC_18, KNX_SECURE_GROUP_KEYS, ReadLv0 | WriteLv0 ),
        new DataProperty( PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE, true, PDT_GENERIC_08, KNX_SECURE_SENDERS, ReadLv0 | WriteLv0 ),
        new FunctionProperty<SecurityInterfaceObject>(this, PID_SECURITY_FAILURES_LOG,
            // Command Callback of PID_SECURITY_FAILURES_LOG
            [](SecurityInterfaceObject* obj, uint8_t* data, uint8_t length, uint8_t* resultData, uint8_t& resultLength) -> void {
                if (!resultData || resultLength < 2)
                {
                    resultLength = 0;
                    return;
                }
                if (!data || length != 3)
                {
                    resultData[0] = ReturnCodes::DataVoid;
                    resultLength = 1;
                    return;
                }
                uint8_t id = data[1];
                uint8_t info = data[2];
                if (id == 0 && info == 0)
                {
                    obj->clearFailureLog();
                    resultData[0] = ReturnCodes::Success;
                    resultData[1] = id;
                    resultLength = 2;
                    return;
                }
                resultData[0] = ReturnCodes::GenericError;
                resultLength = 1;
            },
            // State Callback of PID_SECURITY_FAILURES_LOG
            [](SecurityInterfaceObject* obj, uint8_t* data, uint8_t length, uint8_t* resultData, uint8_t& resultLength) -> void {
                const uint8_t capacity = resultLength;
                if (!resultData || capacity < 2)
                {
                    resultLength = 0;
                    return;
                }
                if (!data || length != 3)
                {
                    resultData[0] = ReturnCodes::DataVoid;
                    resultLength = 1;
                    return;
                }
                uint8_t id = data[1];
                uint8_t info = data[2];

                // failure counters
                if (id == 0 && info == 0)
                {
                    if (capacity < 11)
                    {
                        resultData[0] = ReturnCodes::DataVoid;
                        resultLength = 1;
                        return;
                    }
                    resultData[0] = ReturnCodes::Success;
                    resultData[1] = id;
                    resultData[2] = info;
                    obj->getFailureCounters(&resultData[3]); // Put 8 bytes in the buffer
                    resultLength = 3 + 8;
                    return;
                }
                // query latest failure by index
                else if(id == 1)
                {
                    uint8_t index = info;
                    uint8_t numBytes = capacity >= 3 ?
                        obj->getFromFailureLogByIndex(index, &resultData[3], capacity - 3) : 0;
                    if ( numBytes > 0)
                    {
                        resultData[0] = ReturnCodes::Success;
                        resultData[1] = id;
                        resultData[2] = index;
                        resultLength = 3 + numBytes;
                        return;
                    }
                    resultData[0] = ReturnCodes::DataVoid;
                    resultData[1] = id;
                    resultLength = 2;
                    return;
                }
                resultData[0] = ReturnCodes::GenericError;
                resultLength = 1;
            }),
        // Filled exclusively by runtime per-device provisioning, then replaced by ETS.
        new DataProperty( PID_TOOL_KEY, true, PDT_GENERIC_16, 1, ReadLv0 | WriteLv0 ),
        new DataProperty( PID_SECURITY_REPORT, true, PDT_BITSET8, 1, ReadLv3 | WriteLv0, _secReport ), // Not implemented
        new DataProperty( PID_SECURITY_REPORT_CONTROL, true, PDT_BINARY_INFORMATION, 1, ReadLv3 | WriteLv0, _secReportCtrl ), // Not implemented
        new DataProperty( PID_SEQUENCE_NUMBER_SENDING, true, PDT_GENERIC_06, 1, ReadLv0 | WriteLv0 ), // Updated by our device accordingly
        new DataProperty( PID_ZONE_KEY_TABLE, true, PDT_GENERIC_19, 1, ReadLv0 | WriteLv0 ), // written by ETS
        new DataProperty( PID_GO_SECURITY_FLAGS, true, PDT_GENERIC_01, KNX_SECURE_GROUP_OBJECTS, ReadLv3 | WriteLv0 ),
        new DataProperty( PID_ROLE_TABLE, true, PDT_GENERIC_01, 1, ReadLv3 | WriteLv0 ), // written by ETS
        new DataProperty( PID_ERROR_CODE, false, PDT_ENUM8, 1, ReadLv3 | WriteLv0, (uint8_t)E_NO_FAULT),
        new DataProperty( PID_TOOL_SEQUENCE_NUMBER_SENDING, true, PDT_GENERIC_06, 1, ReadLv0 | WriteLv0 ) // Updated by our device accordingly (non-standardized!)
    };
    initializeProperties(sizeof(properties), properties);
    writeSequenceProperty(false, 1);
    writeSequenceProperty(true, 1);
}

SecurityInterfaceObject::~SecurityInterfaceObject()
{
    clearSecret(_fdsk, sizeof(_fdsk));
    // Unlike borrowed InterfaceObject properties, all SIO properties are created
    // by this constructor and owned here.  Erase secrets before releasing them.
    for (unsigned index = 0; index < _propertyCount; ++index)
    {
        Property* prop = _properties[index];
        if (prop->Id() == PID_TOOL_KEY || prop->Id() == PID_P2P_KEY_TABLE ||
            prop->Id() == PID_GRP_KEY_TABLE || prop->Id() == PID_ZONE_KEY_TABLE)
        {
            DataProperty* secret = static_cast<DataProperty*>(prop);
            uint16_t count = 0;
            uint8_t encodedCount[2];
            if (secret->read(0, 1, encodedCount))
            {
                count = getWord(encodedCount);
                clearSecret(const_cast<uint8_t*>(secret->data()), count * secret->ElementSize());
            }
        }
        delete prop;
        _properties[index] = nullptr;
    }
}

void SecurityInterfaceObject::bindPlatform(Platform& platform)
{
    _platform = &platform;
    _factoryProvisioned = platform.readFactoryDeviceKey(_fdsk);
    // Empty/erased factory slots are not a provisioned device identity.
    uint8_t anySet = 0, anyClear = 0;
    for (uint8_t byte : _fdsk)
    {
        anySet |= byte;
        anyClear |= static_cast<uint8_t>(~byte);
    }
    _factoryProvisioned = _factoryProvisioned && anySet && anyClear;
    if (!_factoryProvisioned)
        clearSecret(_fdsk, sizeof(_fdsk));
    else if (!propertyData(PID_TOOL_KEY))
        property(PID_TOOL_KEY)->write(1, 1, _fdsk);
    _journalHealthy = true;
    loadOutgoingSequences();
}

bool SecurityInterfaceObject::isFactoryProvisioned() const { return _factoryProvisioned; }

bool SecurityInterfaceObject::randomBytes(uint8_t* data, size_t length)
{
    return _platform && _platform->fillRandom(data, length);
}

bool SecurityInterfaceObject::readSequence(uint32_t recordId, uint64_t& value)
{
    uint8_t record[10] = {};
    if (!_platform)
        return false;
    const int length = _platform->readSecurityState(recordId, record, sizeof(record));
    if (length == 0)
    {
        value = 0;
        return true;
    }
    if (length != sizeof(record) || memcmp(record, "SEC1", 4) != 0)
        return false;
    value = sixBytesToUInt64(record + 4);
    return true;
}

bool SecurityInterfaceObject::persistSequence(uint32_t recordId, uint64_t value)
{
    if (!_platform || value > kMaximumSequence)
        return false;
    uint8_t record[10] = {'S', 'E', 'C', '1'};
    sixBytesFromUInt64(value, record + 4);
    return _platform->writeSecurityState(recordId, record, sizeof(record));
}

uint64_t SecurityInterfaceObject::sequenceProperty(bool toolAccess) const
{
    uint8_t bytes[6] = {};
    if (property(toolAccess ? PID_TOOL_SEQUENCE_NUMBER_SENDING : PID_SEQUENCE_NUMBER_SENDING)->read(1, 1, bytes) != 1)
        return 1;
    const uint64_t sequence = sixBytesToUInt64(bytes);
    return sequence ? sequence : 1;
}

void SecurityInterfaceObject::writeSequenceProperty(bool toolAccess, uint64_t sequence)
{
    uint8_t bytes[6] = {};
    sixBytesFromUInt64(sequence > kMaximumSequence ? kMaximumSequence : sequence, bytes);
    property(toolAccess ? PID_TOOL_SEQUENCE_NUMBER_SENDING : PID_SEQUENCE_NUMBER_SENDING)->write(1, 1, bytes);
}

void SecurityInterfaceObject::loadOutgoingSequences()
{
    for (unsigned index = 0; index < 2; ++index)
    {
        uint64_t reserved = 0;
        if (!readSequence(index + 1, reserved))
        {
            _journalHealthy = false;
            continue;
        }
        if (reserved > _reservedSequence[index])
            _reservedSequence[index] = reserved;
        const uint64_t next = _reservedSequence[index] + 1;
        if (next > _nextSequence[index])
            _nextSequence[index] = next;
        const uint64_t restored = sequenceProperty(index != 0);
        if (restored > _nextSequence[index])
            _nextSequence[index] = restored;
        writeSequenceProperty(index != 0, _nextSequence[index]);
    }
}

uint64_t SecurityInterfaceObject::nextSequenceNumber(bool toolAccess) const
{
    const uint64_t next = _nextSequence[toolAccess ? 1 : 0];
    if (!_journalHealthy || next > kMaximumSequence)
        return 0;
    const uint64_t configured = sequenceProperty(toolAccess);
    return configured > next ? configured : next;
}

bool SecurityInterfaceObject::ensureOutgoingSequenceAtLeast(bool toolAccess, uint64_t sequence)
{
    if (!_journalHealthy || !sequence || sequence > kMaximumSequence)
        return false;
    const unsigned index = toolAccess ? 1 : 0;
    // ETS may raise the property while the device is running. Never send or
    // advertise a number below that floor, nor allow a property write to undo
    // the durable/current RAM floor when ETS writes a lower value.
    const uint64_t configured = sequenceProperty(toolAccess);
    if (configured > sequence)
        sequence = configured;
    if (sequence <= _nextSequence[index])
        return _nextSequence[index] <= kMaximumSequence;
    // Persist the consumed prefix before advertising a higher next sequence.
    if (sequence - 1 > _reservedSequence[index] && !persistSequence(index + 1, sequence - 1))
        return false;
    if (sequence - 1 > _reservedSequence[index])
        _reservedSequence[index] = sequence - 1;
    _nextSequence[index] = sequence;
    writeSequenceProperty(toolAccess, sequence);
    return true;
}

bool SecurityInterfaceObject::reserveOutgoingSequence(bool toolAccess, uint64_t& sequence)
{
    sequence = 0;
    if (!_journalHealthy || !_platform || !isFactoryProvisioned())
        return false;
    if (!ensureOutgoingSequenceAtLeast(toolAccess, sequenceProperty(toolAccess)))
        return false;
    const unsigned index = toolAccess ? 1 : 0;
    const uint64_t next = _nextSequence[index];
    if (!next || next > kMaximumSequence)
        return false;
    if (next > _reservedSequence[index])
    {
        const uint64_t available = kMaximumSequence - next;
        const uint64_t advance = KNX_SECURE_SEQUENCE_RESERVATION - 1;
        const uint64_t end = next + (advance < available ? advance : available);
        // Nothing is sent unless the complete reservation is durably committed.
        if (!persistSequence(index + 1, end))
            return false;
        _reservedSequence[index] = end;
    }
    sequence = next;
    _nextSequence[index] = next + 1;
    writeSequenceProperty(toolAccess, next + 1);
    return true;
}

uint64_t SecurityInterfaceObject::configuredReplayFloor(uint16_t sender)
{
    const uint16_t index = indAddressIndex(sender);
    const uint8_t* entry = index ? propertyData(PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE, index) : nullptr;
    uint8_t bytes[6] = {};
    if (entry)
        memcpy(bytes, entry + 2, sizeof(bytes));
    return sixBytesToUInt64(bytes);
}

SecurityInterfaceObject::ReplayState* SecurityInterfaceObject::replayState(bool toolAccess, uint16_t sender)
{
    ReplayState* empty = nullptr;
    const unsigned begin = toolAccess ? KNX_SECURE_SENDERS : 0;
    const unsigned end = toolAccess ? KNX_SECURE_SENDERS + KNX_SECURE_TOOL_SENDERS : KNX_SECURE_SENDERS;
    for (unsigned index = begin; index < end; ++index)
    {
        ReplayState& entry = _replay[index];
        if (entry.occupied && entry.sender == sender)
        {
            const uint64_t floor = toolAccess ? 0 : configuredReplayFloor(sender);
            if (floor > entry.sequence)
                entry.sequence = floor;
            return &entry;
        }
        if (!entry.occupied && !empty)
            empty = &entry;
    }
    // Every accepted floor is durable. A full cache can safely evict a sender
    // and recover its floor from the journal later; historical ETS tool IAs or
    // a replaced sender table must not permanently exhaust the runtime cache.
    if (!empty)
        empty = &_replay[begin];
    uint64_t sequence = 0;
    if (!readSequence((toolAccess ? UINT32_C(0x20000) : UINT32_C(0x10000)) | sender, sequence))
        return nullptr;
    // ETS supplies the initial data replay floor; tools have an independent table.
    if (!toolAccess)
    {
        const uint64_t floor = configuredReplayFloor(sender);
        if (floor > sequence)
            sequence = floor;
    }
    empty->sender = sender;
    empty->sequence = sequence;
    empty->toolAccess = toolAccess;
    empty->occupied = true;
    return empty;
}

uint64_t SecurityInterfaceObject::lastValidSequenceNumber(bool toolAccess, uint16_t sender)
{
    if (!_journalHealthy)
        return kMaximumSequence;
    const unsigned begin = toolAccess ? KNX_SECURE_SENDERS : 0;
    const unsigned end = toolAccess ? KNX_SECURE_SENDERS + KNX_SECURE_TOOL_SENDERS : KNX_SECURE_SENDERS;
    for (unsigned index = begin; index < end; ++index)
    {
        ReplayState& entry = _replay[index];
        if (entry.occupied && entry.sender == sender)
        {
            const uint64_t floor = toolAccess ? 0 : configuredReplayFloor(sender);
            if (floor > entry.sequence)
                entry.sequence = floor;
            return entry.sequence;
        }
    }
    // This is queried BEFORE authentication. Never allocate a tool-sender cache
    // slot here: spoofed IAs with invalid MACs could otherwise exhaust the cache
    // and deny genuine ETS traffic. Only authenticated acceptance inserts slots.
    uint64_t sequence = 0;
    if (!readSequence((toolAccess ? UINT32_C(0x20000) : UINT32_C(0x10000)) | sender, sequence))
        return kMaximumSequence;
    const uint64_t floor = toolAccess ? 0 : configuredReplayFloor(sender);
    return floor > sequence ? floor : sequence;
}

bool SecurityInterfaceObject::acceptIncomingSequence(bool toolAccess, uint16_t sender, uint64_t sequence)
{
    if (!_journalHealthy || !sequence || sequence > kMaximumSequence)
        return false;
    ReplayState* entry = replayState(toolAccess, sender);
    if (!entry || sequence <= entry->sequence)
        return false;
    if (!persistSequence((toolAccess ? UINT32_C(0x20000) : UINT32_C(0x10000)) | sender, sequence))
        return false;
    entry->sequence = sequence;
    if (!toolAccess)
    {
        const uint16_t index = indAddressIndex(sender);
        if (index)
        {
            uint8_t data[8];
            pushWord(sender, data);
            sixBytesFromUInt64(sequence, data + 2);
            property(PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE)->write(index, 1, data);
        }
    }
    return true;
}

bool SecurityInterfaceObject::isKnownSender(uint16_t sender) { return indAddressIndex(sender) != 0; }

void SecurityInterfaceObject::recordFailure(uint8_t code, uint16_t source, uint16_t destination,
                                          uint8_t control, uint64_t sequence)
{
    if (code < 1 || code > 4)
        return;
    uint16_t& counter = _failureCounters[code - 1];
    if (counter != UINT16_MAX)
        ++counter;
    uint8_t* entry = _failureLog[_failureLogNext];
    pushWord(source, entry);
    pushWord(destination, entry + 2);
    entry[4] = control;
    sixBytesFromUInt64(sequence, entry + 5);
    entry[11] = code;
    _failureLogNext = (_failureLogNext + 1) % KNX_SECURE_FAILURE_LOG_SIZE;
    if (_failureLogCount < KNX_SECURE_FAILURE_LOG_SIZE)
        ++_failureLogCount;
}

uint8_t* SecurityInterfaceObject::save(uint8_t* buffer)
{
    buffer = pushByte(_state, buffer);
    buffer = pushByte(_securityModeEnabled, buffer);
    // The legacy image must also skip already reserved numbers if it is restored.
    uint64_t live[2];
    for (unsigned index = 0; index < 2; ++index)
    {
        const uint64_t configured = sequenceProperty(index != 0);
        live[index] = configured > _nextSequence[index] ? configured : _nextSequence[index];
        writeSequenceProperty(index != 0,
            _reservedSequence[index] + 1 > live[index] ? _reservedSequence[index] + 1 : live[index]);
    }
    buffer = InterfaceObject::save(buffer);
    writeSequenceProperty(false, live[0]);
    writeSequenceProperty(true, live[1]);
    return buffer;
}

const uint8_t* SecurityInterfaceObject::restore(const uint8_t* buffer)
{
    uint8_t state = 0;
    buffer = popByte(state, buffer);
    _state = (LoadState)state;

    uint8_t securityModeEnabled = 0;
    buffer = popByte(securityModeEnabled, buffer);
    _securityModeEnabled = securityModeEnabled;

    buffer = InterfaceObject::restore(buffer);
    // Journal counters survive firmware/configuration image replacement and win
    // over any older ETS image.  Do not reset them in masterReset().
    for (ReplayState& entry : _replay)
        entry = ReplayState{};
    if (_platform)
        loadOutgoingSequences();
    return buffer;
}

uint16_t SecurityInterfaceObject::saveSize()
{
    return 2 + InterfaceObject::saveSize();
}

void SecurityInterfaceObject::setSecurityMode(bool enabled)
{
    print("Security mode set to: ");
    println(enabled ? "enabled" : "disabled");
    _securityModeEnabled = enabled;
}

bool SecurityInterfaceObject::isSecurityModeEnabled()
{
    return _securityModeEnabled;
}

void SecurityInterfaceObject::clearFailureLog()
{
    memset(_failureCounters, 0, sizeof(_failureCounters));
    memset(_failureLog, 0, sizeof(_failureLog));
    _failureLogCount = _failureLogNext = 0;
}

void SecurityInterfaceObject::getFailureCounters(uint8_t* data)
{
    for (unsigned index = 0; index < 4; ++index)
        pushWord(_failureCounters[index], data + index * 2);
}

uint8_t SecurityInterfaceObject::getFromFailureLogByIndex(uint8_t index, uint8_t* data, uint8_t maxDataLen)
{
    if (!data || maxDataLen < 12 || index >= _failureLogCount)
        return 0;
    const unsigned slot = (_failureLogNext + KNX_SECURE_FAILURE_LOG_SIZE - 1 - index) % KNX_SECURE_FAILURE_LOG_SIZE;
    memcpy(data, _failureLog[slot], 12);
    return 12;
}

bool SecurityInterfaceObject::isLoaded()
{
    return _state == LS_LOADED;
}

LoadState SecurityInterfaceObject::loadState()
{
    return _state;
}

void SecurityInterfaceObject::loadEvent(const uint8_t* data)
{
    switch (_state)
    {
        case LS_UNLOADED:
            loadEventUnloaded(data);
            break;
        case LS_LOADING:
            loadEventLoading(data);
            break;
        case LS_LOADED:
            loadEventLoaded(data);
            break;
        case LS_ERROR:
            loadEventError(data);
            break;
        default:
            /* do nothing */
            break;
    }
}

void SecurityInterfaceObject::loadEventUnloaded(const uint8_t* data)
{
    uint8_t event = data[0];
    switch (event)
    {
        case LE_NOOP:
        case LE_LOAD_COMPLETED:
        case LE_ADDITIONAL_LOAD_CONTROLS:
        case LE_UNLOAD:
            break;
        case LE_START_LOADING:
            loadState(LS_LOADING);
            break;
        default:
            loadState(LS_ERROR);
            errorCode(E_GOT_UNDEF_LOAD_CMD);
    }
}

void SecurityInterfaceObject::loadEventLoading(const uint8_t* data)
{
    uint8_t event = data[0];
    switch (event)
    {
        case LE_NOOP:
        case LE_START_LOADING:
            break;
        case LE_LOAD_COMPLETED:
            loadState(LS_LOADED);
            break;
        case LE_UNLOAD:
            loadState(LS_UNLOADED);
            break;
        case LE_ADDITIONAL_LOAD_CONTROLS: // Not supported here
        default:
            loadState(LS_ERROR);
            errorCode(E_GOT_UNDEF_LOAD_CMD);
    }
}

void SecurityInterfaceObject::loadEventLoaded(const uint8_t* data)
{
    uint8_t event = data[0];
    switch (event)
    {
        case LE_NOOP:
        case LE_LOAD_COMPLETED:
            break;
        case LE_START_LOADING:
            loadState(LS_LOADING);
            break;
        case LE_UNLOAD:
            loadState(LS_UNLOADED);
            break;
        case LE_ADDITIONAL_LOAD_CONTROLS:
            loadState(LS_ERROR);
            errorCode(E_INVALID_OPCODE);
            break;
        default:
            loadState(LS_ERROR);
            errorCode(E_GOT_UNDEF_LOAD_CMD);
    }
}

void SecurityInterfaceObject::loadEventError(const uint8_t* data)
{
    uint8_t event = data[0];
    switch (event)
    {
        case LE_NOOP:
        case LE_LOAD_COMPLETED:
        case LE_ADDITIONAL_LOAD_CONTROLS:
        case LE_START_LOADING:
            break;
        case LE_UNLOAD:
            loadState(LS_UNLOADED);
            break;
        default:
            loadState(LS_ERROR);
            errorCode(E_GOT_UNDEF_LOAD_CMD);
    }
}

void SecurityInterfaceObject::loadState(LoadState newState)
{
    if (newState == _state)
        return;
    //beforeStateChange(newState);
    _state = newState;
}

void SecurityInterfaceObject::errorCode(ErrorCode errorCode)
{
    uint8_t data = errorCode;
    Property* prop = property(PID_ERROR_CODE);
    prop->write(data);
}

void SecurityInterfaceObject::masterReset(EraseCode eraseCode, uint8_t channel)
{
    (void)channel;
    if (eraseCode != FactoryReset && eraseCode != FactoryResetWithoutIA)
        return;

    /* Keep the element counts long enough for the following writeMemory() to
       overwrite every previously persisted secret with zeroes. The unloaded
       state makes the cleared tables unusable until ETS downloads them again. */
    static const PropertyID sensitiveProperties[] = {
        PID_P2P_KEY_TABLE,
        PID_GRP_KEY_TABLE,
        PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE,
        PID_SECURITY_REPORT,
        PID_SECURITY_REPORT_CONTROL,
        PID_SEQUENCE_NUMBER_SENDING,
        PID_ZONE_KEY_TABLE,
        PID_GO_SECURITY_FLAGS,
        PID_ROLE_TABLE,
        PID_TOOL_SEQUENCE_NUMBER_SENDING,
    };
    uint8_t zeroElement[20] = {};
    for (PropertyID propertyId : sensitiveProperties)
    {
        Property* sensitive = property(propertyId);
        if (sensitive == nullptr || sensitive->ElementSize() > sizeof(zeroElement))
            continue;

        /* Fill the complete property capacity, not only its current count: a prior
           shorter download/reset may have left older serialized bytes in the NVM
           tail. Keeping the all-zero capacity serialized overwrites that tail. */
        for (uint16_t index = 1; index <= sensitive->MaxElements(); ++index)
            sensitive->write(index, 1, zeroElement);
    }

    loadState(LS_UNLOADED);
    setSecurityMode(false);
    clearFailureLog();
    // Outgoing and sender journals intentionally survive reset: the factory key
    // remains identical and therefore restarting sequences could reuse a nonce.
    writeSequenceProperty(false, _nextSequence[0]);
    writeSequenceProperty(true, _nextSequence[1]);
    if (_factoryProvisioned)
        property(PID_TOOL_KEY)->write(1, 1, _fdsk);
    else
    {
        const uint8_t zeroCount[2] = {};
        property(PID_TOOL_KEY)->write(0, 1, zeroCount);
    }
}

const uint8_t* SecurityInterfaceObject::toolKey()
{
    // There is only one tool key
    const uint8_t* toolKey = _factoryProvisioned ? propertyData(PID_TOOL_KEY) : nullptr;
    return toolKey;
}

const uint8_t* SecurityInterfaceObject::p2pKey(uint16_t addressIndex)
{
    if (!isLoaded())
        return nullptr;

    // Get number of entries for this property
    uint16_t numElements = getNumberOfElements(PID_P2P_KEY_TABLE);

    if (numElements > 0)
    {
        uint8_t elementSize = propertySize(PID_P2P_KEY_TABLE);

        // Search for address index
        uint8_t entry[elementSize]; // 2 bytes index + keysize (16 bytes) + 2 bytes(roles) = 20 bytes
        for (int i = 1; i <= numElements; i++)
        {
            property(PID_P2P_KEY_TABLE)->read(i, 1, entry);
            uint16_t index = (entry[0] << 8) | entry[1];
            if (index == addressIndex)
            {
                return propertyData(PID_P2P_KEY_TABLE, i) + sizeof(index);
            }
        }
    }

    return nullptr;
}

const uint8_t* SecurityInterfaceObject::groupKey(uint16_t addressIndex)
{
    if (!isLoaded())
        return nullptr;

    // Get number of entries for this property
    uint16_t numElements = getNumberOfElements(PID_GRP_KEY_TABLE);

    if (numElements > 0)
    {
        uint8_t elementSize = propertySize(PID_GRP_KEY_TABLE);

        // Search for address index
        uint8_t entry[elementSize]; // 2 bytes index + keysize (16 bytes) = 18 bytes
        for (int i = 1; i <= numElements; i++)
        {
            property(PID_GRP_KEY_TABLE)->read(i, 1, entry);
            uint16_t index = ((entry[0] << 8) | entry[1]);
            if (index == addressIndex)
            {
                return propertyData(PID_GRP_KEY_TABLE, i) + sizeof(index);
            }
        }
    }

    return nullptr;
}

uint16_t SecurityInterfaceObject::indAddressIndex(uint16_t indAddr)
{
    // Get number of entries for this property
    uint16_t numElements = getNumberOfElements(PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE);

    if (numElements > 0)
    {
        uint8_t elementSize = propertySize(PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE);

        // Search for individual address
        uint8_t entry[elementSize]; // 2 bytes address + 6 bytes seqno = 8 bytes
        for (int i = 1; i <= numElements; i++)
        {
            property(PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE)->read(i, 1, entry);
            uint16_t addr = (entry[0] << 8) | entry[1];
            if (addr == indAddr)
            {
                return i;
            }
        }
    }

    // Not found
    return 0;
}

void SecurityInterfaceObject::setSequenceNumber(bool toolAccess, uint64_t seqNum)
{
    // Compatibility wrapper; new send paths must check the bool-returning API.
    (void)ensureOutgoingSequenceAtLeast(toolAccess, seqNum);
}

uint16_t SecurityInterfaceObject::getNumberOfElements(PropertyID propId)
{
    // Get number of entries for this property
    uint16_t numElements = 0;

    uint8_t data[sizeof(uint16_t)]; // is sizeof(_currentElements) which is uint16_t
    uint8_t count = property(propId)->read(0, 1, data);

    if (count > 0)
    {
        popWord(numElements, data);
    }

    return numElements;
}

uint64_t SecurityInterfaceObject::getLastValidSequenceNumber(uint16_t deviceAddr)
{
    return lastValidSequenceNumber(false, deviceAddr);
}

void SecurityInterfaceObject::setLastValidSequenceNumber(uint16_t deviceAddr, uint64_t seqNum)
{
    (void)acceptIncomingSequence(false, deviceAddr, seqNum);
}

DataSecurity SecurityInterfaceObject::getGroupObjectSecurity(uint16_t index)
{
    // security table uses same index as group object table
    // Index zero reads the property's two-byte element count, not a one-byte
    // flag. It is not a valid group object and must not overrun the flag buffer.
    if (index == 0)
        return DataSecurity::None;
    uint8_t data[1] = {};

    uint8_t count = property(PID_GO_SECURITY_FLAGS)->read(index, 1, data);

    if (count > 0)
    {
        // write access flags, approved spec. AN158, p.97
        bool conf = (data[0] & 2) == 2;
        bool auth = (data[0] & 1) == 1;
        return conf ? DataSecurity::AuthConf : auth ? DataSecurity::Auth : DataSecurity::None;
    }

    return DataSecurity::None;
}

#endif

