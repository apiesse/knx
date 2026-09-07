#include "bau_systemB.h"
#include "bits.h"
#include "management_policy.h"
#include <string.h>
#include <stdio.h>

enum NmReadSerialNumberType
{
    NM_Read_SerialNumber_By_ProgrammingMode = 0x01,
    NM_Read_SerialNumber_By_ExFactoryState = 0x02,
    NM_Read_SerialNumber_By_PowerReset = 0x03,
    NM_Read_SerialNumber_By_ManufacturerSpecific = 0xFE,
};

static constexpr auto kFunctionPropertyResultBufferMaxSize = 0xFF;
// What the response frames can actually carry. CemiFrame::buffer holds indices 0..263 and apdu.data()
// is buffer+10, so the plain response writes from buffer+13 (<= 251 octets) and the extended one from
// buffer+16 (<= 248). Telling a callee it may write 0xFF let it overrun the frame it is built into.
static constexpr uint8_t kFunctionPropertyResultMax = 251;
static constexpr uint8_t kFunctionPropertyResultMaxExt = 248;
static constexpr auto kRestartProcessTime = 3;

BauSystemB::BauSystemB(Platform& platform): _memory(platform, _deviceObj),
     _appProgram(_memory),
    _platform(platform)
{
    _memory.addSaveRestore(&_appProgram);
}

void BauSystemB::readMemory()
{
    _memory.readMemory();
}

void BauSystemB::writeMemory()
{
    _memory.writeMemory();
}

Platform& BauSystemB::platform()
{
    return _platform;
}

ApplicationProgramObject& BauSystemB::parameters()
{
    return _appProgram;
}

DeviceObject& BauSystemB::deviceObject()
{
    return _deviceObj;
}

uint8_t BauSystemB::checkmasterResetValidity(EraseCode eraseCode, uint8_t channel)
{
    static constexpr uint8_t successCode = 0x00; // Where does this come from? It is the code for "success".
    static constexpr uint8_t invalidEraseCode = 0x02; // Where does this come from? It is the error code for "unspported erase code".

    /* This implementation has one application channel only. Accepting a non-zero
       channel while resetting channel zero would acknowledge a different operation
       from the one actually performed. */
    if (channel != 0)
        return invalidEraseCode;

    switch (eraseCode)
    {
        // All standard erase codes below are implemented by doMasterReset().
        case EraseCode::ConfirmedRestart:
        case EraseCode::ResetAP:
        case EraseCode::ResetIA:
        case EraseCode::ResetLinks:
        case EraseCode::ResetParam:
        case EraseCode::FactoryReset:
        case EraseCode::FactoryResetWithoutIA:
            return successCode;
        default:
        {
            print("Unhandled erase code: ");
            println(eraseCode, HEX);
            return invalidEraseCode;
        }
    }
}

uint8_t BauSystemB::managementAccessLevel()
{
#ifdef KNX_MANAGEMENT_ALLOW_UNGATED
    return 0;
#else
    return KnxManagementPolicy::accessLevel(_deviceObj.progMode());
#endif
}

bool BauSystemB::managementMemoryAccessAllowed()
{
#ifdef KNX_MANAGEMENT_ALLOW_UNGATED
    return true;
#else
    return KnxManagementPolicy::memoryAccessAllowed(_deviceObj.progMode());
#endif
}

bool BauSystemB::managementWriteAllowed()
{
#ifdef KNX_MANAGEMENT_ALLOW_UNGATED
    return true;
#else
    return KnxManagementPolicy::writeAllowed(ReadLv3 | WriteLv3, _deviceObj.progMode());
#endif
}

bool BauSystemB::propertyReadAllowed(const Property* property)
{
    if (property == nullptr)
        return false;
#ifdef KNX_MANAGEMENT_ALLOW_UNGATED
    return true;
#else
    return KnxManagementPolicy::readAllowed(property->Access(), _deviceObj.progMode());
#endif
}

bool BauSystemB::propertyWriteAllowed(const Property* property)
{
    if (property == nullptr || !property->WriteEnable() || !managementWriteAllowed())
        return false;
#ifdef KNX_MANAGEMENT_ALLOW_UNGATED
    return true;
#else
    return KnxManagementPolicy::writeAllowed(property->Access(), _deviceObj.progMode());
#endif
}

bool BauSystemB::propertyCommandAllowed(const Property* property)
{
    if (property == nullptr || !managementWriteAllowed())
        return false;
#ifdef KNX_MANAGEMENT_ALLOW_UNGATED
    return true;
#else
    return KnxManagementPolicy::writeAllowed(property->Access(), _deviceObj.progMode());
#endif
}

void BauSystemB::deviceDescriptorReadIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t descriptorType)
{
    if (descriptorType != 0)
        descriptorType = 0x3f;
    
    uint8_t data[2];
    pushWord(_deviceObj.maskVersion(), data);
    applicationLayer().deviceDescriptorReadResponse(AckRequested, priority, hopType, asap, secCtrl, descriptorType, data);
}
void BauSystemB::memoryRouterWriteIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t number,
                                             uint16_t memoryAddress, uint8_t *data)
{
    if (!managementMemoryAccessAllowed())
        return;
    uint8_t* destination = _memory.toAbsoluteChecked(memoryAddress, number);
    if (number == 0 || data == nullptr || destination == nullptr)
        return;
    print("Writing memory at: ");
    print(memoryAddress, HEX);
    print(" length: ");
    print(number);
    print(" data: ");
    printHex("=>", data, number);
    _memory.writeMemory(memoryAddress, number, data);
    if (_deviceObj.verifyMode())
    {
        print("Sending Read indication");
        memoryRouterReadIndication(priority, hopType, asap, secCtrl, number, memoryAddress, destination);
    }
}

void BauSystemB::memoryRouterReadIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t number,
                                            uint16_t memoryAddress, uint8_t *data)
{
    if (!managementMemoryAccessAllowed())
        number = 0;
    applicationLayer().memoryRouterReadResponse(AckRequested, priority, hopType, asap, secCtrl, number, memoryAddress, data);
}

void BauSystemB::memoryRoutingTableReadIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t number, uint16_t memoryAddress, uint8_t *data)
{
    if (!managementMemoryAccessAllowed())
        number = 0;
    applicationLayer().memoryRoutingTableReadResponse(AckRequested, priority, hopType, asap, secCtrl, number, memoryAddress, data);
}
void BauSystemB::memoryRoutingTableReadIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t number, uint16_t memoryAddress)
{
    if (!managementMemoryAccessAllowed())
    {
        memoryRoutingTableReadIndication(priority, hopType, asap, secCtrl, 0, memoryAddress, nullptr);
        return;
    }
    uint8_t* p = _memory.toAbsoluteChecked(memoryAddress, number);
    if (p == nullptr) number = 0; // OOB read guard: keep the response within NVM
    memoryRoutingTableReadIndication(priority, hopType, asap, secCtrl, number, memoryAddress, p);
}

void BauSystemB::memoryRoutingTableWriteIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t number, uint16_t memoryAddress, uint8_t *data)
{
    if (!managementMemoryAccessAllowed())
        return;
    uint8_t* destination = _memory.toAbsoluteChecked(memoryAddress, number);
    if (number == 0 || data == nullptr || destination == nullptr)
        return;
    print("Writing memory at: ");
    print(memoryAddress, HEX);
    print(" length: ");
    print(number);
    print(" data: ");
    printHex("=>", data, number);
    _memory.writeMemory(memoryAddress, number, data);
    if (_deviceObj.verifyMode())
        memoryRoutingTableReadIndication(priority, hopType, asap, secCtrl, number, memoryAddress, destination);
}

void BauSystemB::memoryWriteIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t number,
    uint16_t memoryAddress, uint8_t * data)
{
    if (!managementMemoryAccessAllowed())
        return;
    uint8_t* destination = _memory.toAbsoluteChecked(memoryAddress, number);
    if (number == 0 || data == nullptr || destination == nullptr)
        return;
    _memory.writeMemory(memoryAddress, number, data);
    if (_deviceObj.verifyMode())
        memoryReadIndication(priority, hopType, asap, secCtrl, number, memoryAddress, destination);
}

void BauSystemB::memoryReadIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t number,
    uint16_t memoryAddress, uint8_t * data)
{
    if (!managementMemoryAccessAllowed())
        number = 0;
    applicationLayer().memoryReadResponse(AckRequested, priority, hopType, asap, secCtrl, number, memoryAddress, data);
}

void BauSystemB::memoryReadIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t number,
    uint16_t memoryAddress)
{
    if (!managementMemoryAccessAllowed())
    {
        applicationLayer().memoryReadResponse(AckRequested, priority, hopType, asap, secCtrl, 0, memoryAddress, nullptr);
        return;
    }
    uint8_t* p = _memory.toAbsoluteChecked(memoryAddress, number);
    if (p == nullptr) number = 0; // OOB read guard: keep the response within NVM
    applicationLayer().memoryReadResponse(AckRequested, priority, hopType, asap, secCtrl, number, memoryAddress, p);
}

void BauSystemB::memoryExtWriteIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t number, uint32_t memoryAddress, uint8_t * data)
{
    if (!managementMemoryAccessAllowed())
    {
        applicationLayer().memoryExtWriteResponse(AckRequested, priority, hopType, asap, secCtrl,
                                                  ReturnCodes::AccessDenied, 0, memoryAddress, nullptr);
        return;
    }
    uint8_t* destination = _memory.toAbsoluteChecked(memoryAddress, number);
    if (number == 0 || data == nullptr || destination == nullptr)
    {
        applicationLayer().memoryExtWriteResponse(AckRequested, priority, hopType, asap, secCtrl,
                                                  ReturnCodes::AddressVoid, 0, memoryAddress, nullptr);
        return;
    }
    _memory.writeMemory(memoryAddress, number, data);

    applicationLayer().memoryExtWriteResponse(AckRequested, priority, hopType, asap, secCtrl,
                                              ReturnCodes::Success, number, memoryAddress, destination);
}

void BauSystemB::memoryExtReadIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t number, uint32_t memoryAddress)
{
    if (!managementMemoryAccessAllowed())
    {
        applicationLayer().memoryExtReadResponse(AckRequested, priority, hopType, asap, secCtrl,
                                                 ReturnCodes::AccessDenied, 0, memoryAddress, nullptr);
        return;
    }
    uint8_t* p = _memory.toAbsoluteChecked(memoryAddress, number);
    ReturnCodes code = (p != nullptr) ? ReturnCodes::Success : ReturnCodes::AddressVoid; // OOB read -> AddressVoid, no data
    if (p == nullptr) number = 0;
    applicationLayer().memoryExtReadResponse(AckRequested, priority, hopType, asap, secCtrl, code, number, memoryAddress, p);
}

void BauSystemB::doMasterReset(EraseCode eraseCode, uint8_t channel)
{
    _deviceObj.masterReset(eraseCode, channel);
    _appProgram.masterReset(eraseCode, channel);
}

void BauSystemB::localFactoryReset()
{
    /* Reset application data but keep the individual address, then persist so the
       change survives the reboot the caller triggers. */
    doMasterReset(EraseCode::FactoryResetWithoutIA, 0);
    writeMemory();
}

void BauSystemB::restartRequestIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, RestartType restartType, EraseCode eraseCode, uint8_t channel)
{
    /* A_Restart is a remote management mutation. The trusted local reset API above
       does not pass through this gate. */
    if (!managementWriteAllowed())
    {
        if (restartType == RestartType::MasterReset)
            applicationLayer().restartResponse(AckRequested, priority, hopType, secCtrl, 0x02, 0);
        return;
    }

    if (restartType == RestartType::BasicRestart)
    {
        println("Basic restart requested");
        if (_beforeRestart != 0)
            _beforeRestart();
    }
    else if (restartType == RestartType::MasterReset)
    {
        uint8_t errorCode = checkmasterResetValidity(eraseCode, channel);
        // We send the restart response now before actually applying the reset values
        // Processing time is kRestartProcessTime (example 3 seconds) that we require for the applying the master reset with restart
        applicationLayer().restartResponse(AckRequested, priority, hopType, secCtrl, errorCode, (errorCode == 0) ? kRestartProcessTime : 0);
        if (errorCode != 0)
            return;
        doMasterReset(eraseCode, channel);
    }
    else
    {
        // Cannot happen as restartType is just one bit
        println("Unhandled restart type.");
        _platform.fatalError();
    }

    // Flush the EEPROM before resetting
    _memory.writeMemory();
    _platform.restart();
}

void BauSystemB::authorizeIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint32_t key)
{
    (void)key;
    /* No classic management-key store exists in this stack. Never interpret an
       arbitrary key as level 0. Physical programming mode is the only trusted
       authorization mechanism by default; 0xFF means no access. */
    const uint8_t level = managementWriteAllowed() ? 0 : 0xFF;
    applicationLayer().authorizeResponse(AckRequested, priority, hopType, asap, secCtrl, level);
}

void BauSystemB::userMemoryReadIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t number, uint32_t memoryAddress)
{
    if (!managementMemoryAccessAllowed())
    {
        applicationLayer().userMemoryReadResponse(AckRequested, priority, hopType, asap, secCtrl, 0, memoryAddress, nullptr);
        return;
    }
    uint8_t* p = _memory.toAbsoluteChecked(memoryAddress, number);
    if (p == nullptr) number = 0; // OOB read guard: keep the response within NVM
    applicationLayer().userMemoryReadResponse(AckRequested, priority, hopType, asap, secCtrl, number, memoryAddress, p);
}

void BauSystemB::userMemoryWriteIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t number, uint32_t memoryAddress, uint8_t* data)
{
    if (!managementMemoryAccessAllowed())
        return;
    _memory.writeMemory(memoryAddress, number, data);

    if (_deviceObj.verifyMode())
        userMemoryReadIndication(priority, hopType, asap, secCtrl, number, memoryAddress);
}

void BauSystemB::propertyDescriptionReadIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t objectIndex,
    uint8_t propertyId, uint8_t propertyIndex)
{
    uint8_t pid = propertyId;
    bool writeEnable = false;
    uint8_t type = 0;
    uint16_t numberOfElements = 0;
    uint8_t access = 0;
    InterfaceObject* obj = getInterfaceObject(objectIndex);
    if (obj)
        obj->readPropertyDescription(pid, propertyIndex, writeEnable, type, numberOfElements, access);

    applicationLayer().propertyDescriptionReadResponse(AckRequested, priority, hopType, asap, secCtrl, objectIndex, pid, propertyIndex,
        writeEnable, type, numberOfElements, access);
}

void BauSystemB::propertyExtDescriptionReadIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl,
    uint16_t objectType, uint16_t objectInstance, uint16_t propertyId, uint8_t descriptionType, uint16_t propertyIndex)
{
    uint8_t pid = propertyId;
    uint8_t pidx = propertyIndex;
    if(propertyId > 0xFF || propertyIndex > 0xFF)
    {
        println("BauSystemB::propertyExtDescriptionReadIndication: propertyId or Idx > 256 are not supported");
        return;
    }
    if(descriptionType != 0)
    {
        println("BauSystemB::propertyExtDescriptionReadIndication: only descriptionType 0 supported");
        return;
    }
    bool writeEnable = false;
    uint8_t type = 0;
    uint16_t numberOfElements = 0;
    uint8_t access = 0;
    InterfaceObject* obj = getInterfaceObject((ObjectType)objectType, objectInstance);
    if (obj)
        obj->readPropertyDescription(pid, pidx, writeEnable, type, numberOfElements, access);

    applicationLayer().propertyExtDescriptionReadResponse(AckRequested, priority, hopType, asap, secCtrl, objectType, objectInstance, pid, pidx,
        descriptionType, writeEnable, type, numberOfElements, access);
}

void BauSystemB::propertyValueWriteIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t objectIndex,
    uint8_t propertyId, uint8_t numberOfElements, uint16_t startIndex, uint8_t* data, uint8_t length)
{
    InterfaceObject* obj = getInterfaceObject(objectIndex);
    if(obj)
    {
        // Memory-safety guard (see propertyValueExtWriteIndication): numberOfElements is attacker-controlled and
        // DataProperty::write() memcpy()s numberOfElements*ElementSize() from `data`; never read past the payload.
        Property* prop = obj->property((PropertyID)propertyId);
        const uint32_t requiredLength = startIndex == 0
                                            ? 2U
                                            : (prop != nullptr
                                                   ? (uint32_t)numberOfElements * prop->ElementSize()
                                                   : UINT32_MAX);
        // PID_LOAD_STATE_CONTROL (PDT_CONTROL, ElementSize reports 1) reaches additionalLoadControls, which reads
        // 8 octets for LE_ADDITIONAL_LOAD_CONTROLS; ElementSize does not bound that -> drop a short/corrupt one.
        bool loadCtrlShort = (propertyId == PID_LOAD_STATE_CONTROL && data != nullptr && length >= 1
                              && data[0] == LE_ADDITIONAL_LOAD_CONTROLS && length < 8);
        if (!loadCtrlShort && data != nullptr && propertyWriteAllowed(prop)
            && requiredLength <= length)
            obj->writeProperty((PropertyID)propertyId, startIndex, data, numberOfElements);
        else
            numberOfElements = 0;
    }
    else
        numberOfElements = 0;
    propertyValueReadIndication(priority, hopType, asap, secCtrl, objectIndex, propertyId, numberOfElements, startIndex);
}

void BauSystemB::propertyValueExtWriteIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, ObjectType objectType, uint8_t objectInstance,
    uint8_t propertyId, uint8_t numberOfElements, uint16_t startIndex, uint8_t* data, uint8_t length, bool confirmed)
{
    uint8_t returnCode = ReturnCodes::Success;

    InterfaceObject* obj = getInterfaceObject(objectType, objectInstance);
    if(obj)
    {
        // Memory-safety: numberOfElements is attacker-controlled; DataProperty::write() clamps it only against
        // _maxElements and then memcpy()s numberOfElements*ElementSize() from `data`, over-reading the
        // `length`-octet payload (and persisting the stolen bytes into the property). Reject a write that
        // claims more element data than the payload carries.
        Property* prop = obj->property((PropertyID)propertyId);
        const uint32_t requiredLength = startIndex == 0
                                            ? 2U
                                            : (prop != nullptr
                                                   ? (uint32_t)numberOfElements * prop->ElementSize()
                                                   : UINT32_MAX);
        // see propertyValueWriteIndication: the LE_ADDITIONAL_LOAD_CONTROLS callback reads 8 octets (PDT_CONTROL
        // ElementSize reports 1 and does not bound it) -> reject a short/corrupt load-control write.
        bool loadCtrlShort = (propertyId == PID_LOAD_STATE_CONTROL && data != nullptr && length >= 1
                              && data[0] == LE_ADDITIONAL_LOAD_CONTROLS && length < 8);
        if (prop == nullptr)
            returnCode = ReturnCodes::AddressVoid;
        else if (!propertyWriteAllowed(prop))
            returnCode = prop->WriteEnable() ? ReturnCodes::AccessDenied : ReturnCodes::AccessReadOnly;
        else if (data == nullptr || loadCtrlShort || requiredLength > length)
            returnCode = ReturnCodes::DataOverflow;
        else
        {
            uint8_t writtenElements = numberOfElements;
            obj->writeProperty((PropertyID)propertyId, startIndex, data, writtenElements);
            if (writtenElements == 0)
            {
                // The property callback rejected the value itself (as opposed to
                // the payload exceeding the addressed storage checked above).
                returnCode = ReturnCodes::DataVoid;
                numberOfElements = 0;
            }
            else
                numberOfElements = writtenElements;
        }
    }
    else
        returnCode = ReturnCodes::AddressVoid;

    if (confirmed)
    {
        applicationLayer().propertyValueExtWriteConResponse(AckRequested, priority, hopType, asap, secCtrl, objectType, objectInstance, propertyId, numberOfElements, startIndex, returnCode);
    }
}

void BauSystemB::propertyValueReadIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t objectIndex,
    uint8_t propertyId, uint8_t numberOfElements, uint16_t startIndex)
{
    uint8_t size = 0;
    uint8_t elementCount = numberOfElements;
#ifdef LOG_KNX_PROP
    print("propertyValueReadIndication: ObjIdx ");
    print(objectIndex);
    print(" propId ");
    print(propertyId);
    print(" num ");
    print(numberOfElements);
    print(" start ");
    print(startIndex);
#endif

    InterfaceObject* obj = getInterfaceObject(objectIndex);
    Property* prop = obj != nullptr ? obj->property((PropertyID)propertyId) : nullptr;
    if (obj && elementCount > 0 && propertyReadAllowed(prop))
    {
        uint8_t elementSize = obj->propertySize((PropertyID)propertyId);
        if (startIndex > 0)
        {
            // EC: clamp count so elementSize*count fits the uint8 buffer -> no size truncation mismatch and no
            // oversized stack VLA (a PropertyValueRead with a large count would otherwise overflow data[]).
            uint16_t total = (uint16_t)elementSize * numberOfElements;
            if (total > 249)
            {
                elementCount = elementSize ? (uint8_t)(249 / elementSize) : 0;
                total = (uint16_t)elementSize * elementCount;
            }
            size = (uint8_t)total;
        }
        else
            size = sizeof(uint16_t); // size of property array entry 0 which contains the current number of elements
    }
    else
        elementCount = 0;

    uint8_t data[size];
    if(obj && elementCount > 0 && propertyReadAllowed(prop))
        obj->readProperty((PropertyID)propertyId, startIndex, elementCount, data);

    if (elementCount == 0)
        size = 0;
    
    applicationLayer().propertyValueReadResponse(AckRequested, priority, hopType, asap, secCtrl, objectIndex, propertyId, elementCount,
                                        startIndex, data, size);
}

void BauSystemB::propertyValueExtReadIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, ObjectType objectType, uint8_t objectInstance,
    uint8_t propertyId, uint8_t numberOfElements, uint16_t startIndex)
{
    uint8_t size = 0;
    uint8_t elementCount = numberOfElements;
    InterfaceObject* obj = getInterfaceObject(objectType, objectInstance);
    Property* prop = obj != nullptr ? obj->property((PropertyID)propertyId) : nullptr;
    if (obj && propertyReadAllowed(prop))
    {
        uint8_t elementSize = obj->propertySize((PropertyID)propertyId);
        if (startIndex > 0)
        {
            // EC: clamp count so elementSize*count fits the uint8 buffer -> no size truncation mismatch and no
            // oversized stack VLA (a PropertyValueExtRead with numberOfElements up to 255 over the tunnel would
            // otherwise overflow data[]).
            uint16_t total = (uint16_t)elementSize * numberOfElements;
            if (total > 245)
            {
                elementCount = elementSize ? (uint8_t)(245 / elementSize) : 0;
                total = (uint16_t)elementSize * elementCount;
            }
            size = (uint8_t)total;
        }
        else
            size = sizeof(uint16_t); // size of propert array entry 0 which is the size
    }
    else
        elementCount = 0;

    uint8_t data[size];
    if(obj && propertyReadAllowed(prop))
        obj->readProperty((PropertyID)propertyId, startIndex, elementCount, data);

    if (elementCount == 0)
        size = 0;

    applicationLayer().propertyValueExtReadResponse(AckRequested, priority, hopType, asap, secCtrl, objectType, objectInstance, propertyId, elementCount,
                                           startIndex, data, size);
}

void BauSystemB::functionPropertyCommandIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t objectIndex,
                                                   uint8_t propertyId, uint8_t* data, uint8_t length)
{
    uint8_t resultData[kFunctionPropertyResultBufferMaxSize];
    uint8_t resultLength = kFunctionPropertyResultMax; // tell the callee what the response can carry

    if (!managementWriteAllowed())
    {
        resultData[0] = ReturnCodes::AccessDenied;
        applicationLayer().functionPropertyStateResponse(AckRequested, priority, hopType, asap, secCtrl,
                                                         objectIndex, propertyId, resultData, 1);
        return;
    }

    bool handled = false;

    InterfaceObject* obj = getInterfaceObject(objectIndex);
    if(obj)
    {
        Property* prop = obj->property((PropertyID)propertyId);
        if (propertyCommandAllowed(prop) && prop->Type() == PDT_FUNCTION)
        {
            obj->command((PropertyID)propertyId, data, length, resultData, resultLength);
            handled = true;
        }
        else
        {
            /* A registered fallback may only represent an unknown PID. Never
               let it override an existing property's declared access/type. */
            if(prop == nullptr && _functionProperty != 0)
                if(_functionProperty(objectIndex, propertyId, length, data, resultData, resultLength))
                    handled = true;

            // 03_03_07 3.4.7.3 p.88: a property that exists but is not PDT_FUNCTION shall be answered with
            // a response carrying neither return code nor data. An unknown PID is not covered -> stay silent.
            if (!handled && prop != nullptr)
            {
                resultLength = 0;
                handled = true;
            }
        }
    } else {
        if(_functionProperty != 0)
            if(_functionProperty(objectIndex, propertyId, length, data, resultData, resultLength))
                handled = true;
    }

    //only return a value it was handled by a property or function
    if(handled)
        applicationLayer().functionPropertyStateResponse(AckRequested, priority, hopType, asap, secCtrl, objectIndex, propertyId, resultData, resultLength);
}

void BauSystemB::functionPropertyStateIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, uint8_t objectIndex,
                                                 uint8_t propertyId, uint8_t* data, uint8_t length)
{
    uint8_t resultData[kFunctionPropertyResultBufferMaxSize];
    uint8_t resultLength = kFunctionPropertyResultMax; // tell the callee what the response can carry

    // Was initialised to true, so the "only answer if handled" check below never suppressed anything and
    // a response was built with the untouched resultLength. The command twin above initialises it false.
    bool handled = false;

    InterfaceObject* obj = getInterfaceObject(objectIndex);
    if(obj)
    {
        Property* prop = obj->property((PropertyID)propertyId);
        if (propertyReadAllowed(prop) && prop->Type() == PDT_FUNCTION)
        {
            obj->state((PropertyID)propertyId, data, length, resultData, resultLength);
            handled = true;
        }
        else
        {
            /* Unknown virtual properties have no access metadata. Fail closed
               outside the physical programming-mode management window, and do
               not let a callback bypass an existing property's policy. */
            if(prop == nullptr && managementWriteAllowed() && _functionPropertyState != 0)
                if(_functionPropertyState(objectIndex, propertyId, length, data, resultData, resultLength))
                    handled = true;

            // 03_03_07 3.4.7.3 p.88: a property that exists but is not PDT_FUNCTION shall be answered with
            // a response carrying neither return code nor data. An unknown PID is not covered -> stay silent.
            if (!handled && prop != nullptr)
            {
                resultLength = 0;
                handled = true;
            }
        }
    } else {
        if(managementWriteAllowed() && _functionPropertyState != 0)
            if(_functionPropertyState(objectIndex, propertyId, length, data, resultData, resultLength))
                handled = true;
    }

    //only return a value it was handled by a property or function
    if(handled)
        applicationLayer().functionPropertyStateResponse(AckRequested, priority, hopType, asap, secCtrl, objectIndex, propertyId, resultData, resultLength);
}

void BauSystemB::functionPropertyExtCommandIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, ObjectType objectType, uint8_t objectInstance,
                                                      uint8_t propertyId, uint8_t* data, uint8_t length)
{
    if (length == 0) return; // the reserved input octet data[0] must be present; drop a truncated ext function-property command
    uint8_t resultData[kFunctionPropertyResultBufferMaxSize];
    uint8_t resultLength = 1; // we always have to include the return code at least

    if (!managementWriteAllowed())
    {
        resultData[0] = ReturnCodes::AccessDenied;
        applicationLayer().functionPropertyExtStateResponse(AckRequested, priority, hopType, asap, secCtrl,
                                                            objectType, objectInstance, propertyId,
                                                            resultData, resultLength);
        return;
    }

    InterfaceObject* obj = getInterfaceObject(objectType, objectInstance);
    if(obj)
    {
        Property* prop = obj->property((PropertyID)propertyId);
        PropertyDataType propType = prop != nullptr ? prop->Type() : (PropertyDataType)0; // null (unknown PID) -> non-FUNCTION sentinel, never deref null

        if (prop == nullptr)
        {
            resultData[0] = ReturnCodes::AddressVoid;
        }
        else if (propType == PDT_FUNCTION && !propertyCommandAllowed(prop))
        {
            resultData[0] = ReturnCodes::AccessDenied;
        }
        else if (propType == PDT_FUNCTION)
        {
            // The first byte is reserved and 0 for PDT_FUNCTION
            uint8_t reservedByte = data[0];
            if (reservedByte != 0x00)
            {
                resultData[0] = ReturnCodes::DataVoid;
            }
            else
            {
                resultLength = kFunctionPropertyResultMaxExt; // tell the callee what the response can carry
                obj->command((PropertyID)propertyId, data, length, resultData, resultLength);
                // resultLength was modified by the callee
            }
        }
        else if (propType == PDT_CONTROL && !propertyWriteAllowed(prop))
        {
            resultData[0] = prop->WriteEnable() ? ReturnCodes::AccessDenied : ReturnCodes::AccessReadOnly;
        }
        else if (propType == PDT_CONTROL)
        {
            uint8_t count = 1;
            // guard: LE_ADDITIONAL_LOAD_CONTROLS reads 8 octets (see propertyValueWriteIndication); skip a short/corrupt one
            if (propertyId == PID_LOAD_STATE_CONTROL && length >= 1 && data[0] == LE_ADDITIONAL_LOAD_CONTROLS && length < 8)
                count = 0;
            else
                obj->writeProperty((PropertyID)propertyId, 1, data, count);
            if (count == 1)
            {
                // Read the current state (one byte only) for the response
                obj->readProperty((PropertyID)propertyId, 1, count, &resultData[1]);
                resultLength = count ? 2 : 1;
                resultData[0] = count ? ReturnCodes::Success : ReturnCodes::DataVoid;
            }
            else
            {
                resultData[0] = ReturnCodes::AddressVoid;
            }
        }
        else
        {
            resultData[0] = ReturnCodes::DataTypeConflict;
        }
    }
    else
    {
        resultData[0] = ReturnCodes::GenericError;
    }

    applicationLayer().functionPropertyExtStateResponse(AckRequested, priority, hopType, asap, secCtrl, objectType, objectInstance, propertyId, resultData, resultLength);
}

void BauSystemB::functionPropertyExtStateIndication(Priority priority, HopCountType hopType, uint16_t asap, const SecurityControl &secCtrl, ObjectType objectType, uint8_t objectInstance,
                                                    uint8_t propertyId, uint8_t* data, uint8_t length)
{
    if (length == 0) return; // the reserved input octet data[0] must be present; drop a truncated ext function-property state read
    uint8_t resultData[kFunctionPropertyResultBufferMaxSize];
    // Like the ExtCommand twin: start at the return code alone. The error paths below set only
    // resultData[0] and never touch resultLength, and 03_03_07 3.4.8.3 p.93 says such a response carries
    // no data field -- announcing the full buffer here would put uninitialised stack on the bus.
    // Only the length is fixed here: the codes those paths send still differ from the table on p.94,
    // which defines E_ADDRESS_VOID for a missing object or property. Changing them is a wire change.
    uint8_t resultLength = 1;

    InterfaceObject* obj = getInterfaceObject(objectType, objectInstance);
    if(obj)
    {
        Property* prop = obj->property((PropertyID)propertyId);
        PropertyDataType propType = prop != nullptr ? prop->Type() : (PropertyDataType)0; // null (unknown PID) -> non-FUNCTION sentinel, never deref null

        if (!propertyReadAllowed(prop))
        {
            resultData[0] = prop == nullptr ? ReturnCodes::AddressVoid : ReturnCodes::AccessDenied;
        }
        else if (propType == PDT_FUNCTION)
        {
            // The first byte is reserved and 0 for PDT_FUNCTION
            uint8_t reservedByte = data[0];
            if (reservedByte != 0x00)
            {
                resultData[0] = ReturnCodes::DataVoid;
            }
            else
            {
                resultLength = kFunctionPropertyResultMaxExt; // tell the callee what the response can carry
                obj->state((PropertyID)propertyId, data, length, resultData, resultLength);
                // resultLength was modified by the callee
            }
        }
        else if (propType == PDT_CONTROL)
        {
            uint8_t count = 1;
            // Read the current state (one byte only) for the response
            obj->readProperty((PropertyID)propertyId, 1, count, &resultData[1]);
            resultLength = count ? 2 : 1;
            resultData[0] = count ? ReturnCodes::Success : ReturnCodes::DataVoid;
        }
        else
        {
            resultData[0] = ReturnCodes::DataTypeConflict;
        }
    }
    else
    {
        resultData[0] = ReturnCodes::GenericError;
    }

    applicationLayer().functionPropertyExtStateResponse(AckRequested, priority, hopType, asap, secCtrl, objectType, objectInstance, propertyId, resultData, resultLength);
}

void BauSystemB::individualAddressReadIndication(HopCountType hopType, const SecurityControl &secCtrl)
{
    if (_deviceObj.progMode())
        applicationLayer().individualAddressReadResponse(AckRequested, hopType, secCtrl);
}

void BauSystemB::individualAddressWriteIndication(HopCountType hopType, const SecurityControl &secCtrl, uint16_t newaddress)
{
    if (_deviceObj.progMode())
        _deviceObj.individualAddress(newaddress);
}

void BauSystemB::individualAddressSerialNumberWriteIndication(Priority priority, HopCountType hopType, const SecurityControl &secCtrl, uint16_t newIndividualAddress,
                                                          uint8_t* knxSerialNumber)
{
    // If the received serial number matches our serial number
    // then store the received new individual address in the device object
    if (managementWriteAllowed()
        && !memcmp(knxSerialNumber, _deviceObj.propertyData(PID_SERIAL_NUMBER), 6))
        _deviceObj.individualAddress(newIndividualAddress);
}

void BauSystemB::individualAddressSerialNumberReadIndication(Priority priority, HopCountType hopType, const SecurityControl &secCtrl, uint8_t* knxSerialNumber)
{
    // If the received serial number matches our serial number
    // then send a response with the serial number. The domain address is set to 0 for closed media.
    // An open medium BAU has to override this method and provide a proper domain address.
    if (!memcmp(knxSerialNumber, _deviceObj.propertyData(PID_SERIAL_NUMBER), 6))
    {
        uint8_t emptyDomainAddress[2] = {0x00};
        applicationLayer().IndividualAddressSerialNumberReadResponse(priority, hopType, secCtrl, emptyDomainAddress, knxSerialNumber);
    }
}

void BauSystemB::addSaveRestore(SaveRestore* obj)
{
    _memory.addSaveRestore(obj);
}

bool BauSystemB::restartRequest(uint16_t asap, const SecurityControl secCtrl)
{
    if (applicationLayer().isConnected())
        return false;
    _restartState = Connecting; // order important, has to be set BEFORE connectRequest
    _restartSecurity = secCtrl;
    applicationLayer().connectRequest(asap, SystemPriority);
    applicationLayer().deviceDescriptorReadRequest(AckRequested, SystemPriority, NetworkLayerParameter, asap, secCtrl, 0);
    return true;
}

void BauSystemB::connectConfirm(uint16_t tsap)
{
    if (_restartState == Connecting)
    {
        /* restart connection is confirmed, go to the next state */
        _restartState = Connected;
        _restartDelay = millis();
    }
    else
    {
        _restartState = Idle;
    }
}

void BauSystemB::nextRestartState()
{
    switch (_restartState)
    {
        case Idle:
            /* inactive state, do nothing */
            break;
        case Connecting:
            /* wait for connection, we do nothing here */
            break;
        case Connected:
            /* connection confirmed, we send restartRequest, but we wait a moment (sending ACK etc)... */
            if (millis() - _restartDelay > 30)
            {
                applicationLayer().restartRequest(AckRequested, SystemPriority, NetworkLayerParameter, _restartSecurity);
                _restartState = Restarted;
                _restartDelay = millis();
            }
            break;
        case Restarted:
            /* restart is finished, we send a disconnect */
            if (millis() - _restartDelay > 30)
            {
                applicationLayer().disconnectRequest(SystemPriority);
                _restartState = Idle;
            }
        default:
            break;
    }
}

void BauSystemB::systemNetworkParameterReadIndication(Priority priority, HopCountType hopType, const SecurityControl &secCtrl, uint16_t objectType,
                                                      uint16_t propertyId, uint8_t* testInfo, uint16_t testInfoLength)
{
    uint8_t operand;

    popByte(operand, testInfo + 1); // First byte (+ 0) contains only 4 reserved bits (0)

    // See KNX spec. 3.5.2 p.33 (Management Procedures: Procedures with A_SystemNetworkParameter_Read)
    switch((NmReadSerialNumberType)operand)
    {
        case NM_Read_SerialNumber_By_ProgrammingMode: // NM_Read_SerialNumber_By_ProgrammingMode
            // Only send a reply if programming mode is on
            if (_deviceObj.progMode() && (objectType == OT_DEVICE) && (propertyId == PID_SERIAL_NUMBER))
            {
                // Send reply. testResult data is KNX serial number
                applicationLayer().systemNetworkParameterReadResponse(priority, hopType, secCtrl, objectType, propertyId,
                                                             testInfo, testInfoLength, (uint8_t*)_deviceObj.propertyData(PID_SERIAL_NUMBER), 6);
            }
        break;

        case NM_Read_SerialNumber_By_ExFactoryState: // NM_Read_SerialNumber_By_ExFactoryState
        break;

        case NM_Read_SerialNumber_By_PowerReset: // NM_Read_SerialNumber_By_PowerReset
        break;

        case NM_Read_SerialNumber_By_ManufacturerSpecific: // Manufacturer specific use of A_SystemNetworkParameter_Read
        break;
    }
}

void BauSystemB::systemNetworkParameterReadLocalConfirm(Priority priority, HopCountType hopType, const SecurityControl &secCtrl, uint16_t objectType,
                                                         uint16_t propertyId, uint8_t* testInfo, uint16_t testInfoLength, bool status)
{
}

void BauSystemB::propertyValueRead(ObjectType objectType, uint8_t objectInstance, uint8_t propertyId,
                                   uint8_t &numberOfElements, uint16_t startIndex,
                                   uint8_t **data, uint32_t &length)
{
    uint32_t size = 0;
    uint8_t elementCount = numberOfElements;

    InterfaceObject* obj = getInterfaceObject(objectType, objectInstance);

    Property* prop = obj != nullptr ? obj->property((PropertyID)propertyId) : nullptr;
    if (obj && propertyReadAllowed(prop))
    {
        uint8_t elementSize = obj->propertySize((PropertyID)propertyId);
        if (startIndex > 0)
            size = elementSize * numberOfElements;
        else
            size = sizeof(uint16_t); // size of property array entry 0 which contains the current number of elements
        *data = new uint8_t [size];
        obj->readProperty((PropertyID)propertyId, startIndex, elementCount, *data);
    }
    else
    {
        elementCount = 0;
        *data = nullptr;
    }

    numberOfElements = elementCount;
    length = size;
}

void BauSystemB::propertyValueWrite(ObjectType objectType, uint8_t objectInstance, uint8_t propertyId,
                                    uint8_t &numberOfElements, uint16_t startIndex,
                                    uint8_t* data, uint32_t length)
{
    InterfaceObject* obj =  getInterfaceObject(objectType, objectInstance);
    if(obj)
    {
        // Memory-safety (same class as propertyValue(Ext)WriteIndication, but this is the cEMI-server feeder):
        // the length is passed but DataProperty::write() clamps count only against _maxElements and then
        // memcpy()s numberOfElements*ElementSize() from `data`. Reject a write claiming more element data than
        // the `length`-octet payload carries -> no over-read past the cEMI request buffer, no info-leak persisted.
        Property* prop = obj->property((PropertyID)propertyId);
        const uint32_t requiredLength = startIndex == 0
                                            ? 2U
                                            : (prop != nullptr
                                                   ? (uint32_t)numberOfElements * prop->ElementSize()
                                                   : UINT32_MAX);
        // see propertyValueWriteIndication: bound the LE_ADDITIONAL_LOAD_CONTROLS 8-octet read against the payload
        bool loadCtrlShort = (propertyId == PID_LOAD_STATE_CONTROL && data != nullptr && length >= 1
                              && data[0] == LE_ADDITIONAL_LOAD_CONTROLS && length < 8);
        if (prop == nullptr || data == nullptr || !propertyWriteAllowed(prop) || loadCtrlShort
            || requiredLength > length)
            numberOfElements = 0;
        else
            obj->writeProperty((PropertyID)propertyId, startIndex, data, numberOfElements);
    }
    else
        numberOfElements = 0;
}

Memory& BauSystemB::memory()
{
    return _memory;
}

void BauSystemB::versionCheckCallback(VersionCheckCallback func)
{
    _memory.versionCheckCallback(func);
}

VersionCheckCallback BauSystemB::versionCheckCallback()
{
    return _memory.versionCheckCallback();
}

void BauSystemB::beforeRestartCallback(BeforeRestartCallback func)
{
    _beforeRestart = func;
}

BeforeRestartCallback BauSystemB::beforeRestartCallback()
{
    return _beforeRestart;
}

void BauSystemB::functionPropertyCallback(FunctionPropertyCallback func)
{
    _functionProperty = func;
}

FunctionPropertyCallback BauSystemB::functionPropertyCallback()
{
    return _functionProperty;
}
void BauSystemB::functionPropertyStateCallback(FunctionPropertyCallback func)
{
    _functionPropertyState = func;
}

FunctionPropertyCallback BauSystemB::functionPropertyStateCallback()
{
    return _functionPropertyState;
}
