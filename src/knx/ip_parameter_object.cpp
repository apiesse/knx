#include "ip_parameter_object.h"
#ifdef USE_IP
#include "device_object.h"
#include "platform.h"
#include "bits.h"
#include "data_property.h"
#include "callback_property.h"
#include "function_property.h"
#include <cstring>

// 224.0.23.12
#define DEFAULT_MULTICAST_ADDR ((uint32_t)0xE000170C)

IpParameterObject::IpParameterObject(DeviceObject& deviceObject, Platform& platform): _deviceObject(deviceObject),
    _platform(platform)
{
    Property* properties[] =
    {
        new DataProperty(PID_OBJECT_TYPE, false, PDT_UNSIGNED_INT, 1, ReadLv3 | WriteLv0, (uint16_t)OT_IP_PARAMETER),
        new DataProperty(PID_PROJECT_INSTALLATION_ID, true, PDT_UNSIGNED_INT, 1, ReadLv3 | WriteLv3),
        new CallbackProperty<IpParameterObject>(this, PID_KNX_INDIVIDUAL_ADDRESS, true, PDT_UNSIGNED_INT, 1, ReadLv3 | WriteLv3,
            [](IpParameterObject* io, uint16_t start, uint8_t count, uint8_t* data) -> uint8_t 
            {
                if(start == 0)
                {
                    uint16_t currentNoOfElements = 1;
                    pushWord(currentNoOfElements, data);
                    return 1;
                }
                // TODO: get property of deviceobject and use it
                pushWord(io->_deviceObject.individualAddress(), data);
                return 1;
            },
            [](IpParameterObject* io, uint16_t start, uint8_t count, const uint8_t* data) -> uint8_t 
            { 
                io->_deviceObject.individualAddress(getWord(data));
                return 1; 
            }),
#ifdef KNX_TUNNELING
        new DataProperty(PID_ADDITIONAL_INDIVIDUAL_ADDRESSES, true, PDT_UNSIGNED_INT, KNX_TUNNELING, ReadLv3 | WriteLv3),
        new CallbackProperty<IpParameterObject>(this, PID_TUNNELING_ADDRESSES, false, PDT_UNSIGNED_CHAR, KNX_TUNNELING, ReadLv3 | WriteLv0,
            [](IpParameterObject*, uint16_t start, uint8_t count, uint8_t* data) -> uint8_t {
                if (start == 0) { pushWord(KNX_TUNNELING, data); return 1; }
                if (start > KNX_TUNNELING || count > KNX_TUNNELING - start + 1) return 0;
                for (uint8_t i = 0; i < count; ++i) data[i] = start + i;
                return count;
            }),
        new DataProperty(PID_CUSTOM_RESERVED_TUNNELS_CTRL, true, PDT_UNSIGNED_CHAR, KNX_TUNNELING, ReadLv3 | WriteLv3), // custom propertiy to control the stacks behaviour for reserverd tunnels, not in Spec (PID >= 200)
        new DataProperty(PID_CUSTOM_RESERVED_TUNNELS_IP, true, PDT_UNSIGNED_LONG, KNX_TUNNELING, ReadLv3 | WriteLv3), // custom propertiy to control the stacks behaviour for reserverd tunnels, not in Spec (PID >= 200)
#endif
        new DataProperty(PID_CURRENT_IP_ASSIGNMENT_METHOD, false, PDT_UNSIGNED_CHAR, 0, ReadLv3 | WriteLv3),
        new DataProperty(PID_IP_ASSIGNMENT_METHOD, true, PDT_UNSIGNED_CHAR, 1, ReadLv3 | WriteLv3),
        new DataProperty(PID_IP_CAPABILITIES, true, PDT_BITSET8, 0, ReadLv3 | WriteLv1),    // must be set by application due to capabilities of the used ip stack
        new CallbackProperty<IpParameterObject>(this, PID_CURRENT_IP_ADDRESS, false, PDT_UNSIGNED_LONG, 1, ReadLv3 | WriteLv0,
            [](IpParameterObject* io, uint16_t start, uint8_t count, uint8_t* data) -> uint8_t 
            { 
                if(start == 0)
                {
                    uint16_t currentNoOfElements = 1;
                    pushWord(currentNoOfElements, data);
                    return 1;
                }

                pushInt(htonl(io->_platform.currentIpAddress()), data);
                return 1;
            }),
        new CallbackProperty<IpParameterObject>(this, PID_CURRENT_SUBNET_MASK, false, PDT_UNSIGNED_LONG, 1, ReadLv3 | WriteLv0,
            [](IpParameterObject* io, uint16_t start, uint8_t count, uint8_t* data) -> uint8_t 
            { 
                if(start == 0)
                {
                    uint16_t currentNoOfElements = 1;
                    pushWord(currentNoOfElements, data);
                    return 1;
                }

                pushInt(htonl(io->_platform.currentSubnetMask()), data);
                return 1;
            }),
        new CallbackProperty<IpParameterObject>(this, PID_CURRENT_DEFAULT_GATEWAY, false, PDT_UNSIGNED_LONG, 1, ReadLv3 | WriteLv0,
            [](IpParameterObject* io, uint16_t start, uint8_t count, uint8_t* data) -> uint8_t 
            { 
                if(start == 0)
                {
                    uint16_t currentNoOfElements = 1;
                    pushWord(currentNoOfElements, data);
                    return 1;
                }

                pushInt(htonl(io->_platform.currentDefaultGateway()), data);
                return 1;
            }),
        new DataProperty(PID_IP_ADDRESS, true, PDT_UNSIGNED_LONG, 1, ReadLv3 | WriteLv3),
        new DataProperty(PID_SUBNET_MASK, true, PDT_UNSIGNED_LONG, 1, ReadLv3 | WriteLv3),
        new DataProperty(PID_DEFAULT_GATEWAY, true, PDT_UNSIGNED_LONG, 1, ReadLv3 | WriteLv3),
        new CallbackProperty<IpParameterObject>(this, PID_MAC_ADDRESS, false, PDT_GENERIC_06, 1, ReadLv3 | WriteLv0,
            [](IpParameterObject* io, uint16_t start, uint8_t count, uint8_t* data) -> uint8_t 
            { 
                if(start == 0)
                {
                    uint16_t currentNoOfElements = 1;
                    pushWord(currentNoOfElements, data);
                    return 1;
                }

                io->_platform.macAddress(data);
                return 1;
            }),
        new CallbackProperty<IpParameterObject>(this, PID_SYSTEM_SETUP_MULTICAST_ADDRESS, false, PDT_UNSIGNED_LONG, 1, ReadLv3 | WriteLv0,
            [](IpParameterObject* io, uint16_t start, uint8_t count, uint8_t* data) -> uint8_t 
            { 
                if(start == 0)
                {
                    uint16_t currentNoOfElements = 1;
                    pushWord(currentNoOfElements, data);
                    return 1;
                }

                pushInt(DEFAULT_MULTICAST_ADDR, data);
                return 1;
            }),
        new DataProperty(PID_ROUTING_MULTICAST_ADDRESS, true, PDT_UNSIGNED_LONG, 1, ReadLv3 | WriteLv3, DEFAULT_MULTICAST_ADDR),
        new DataProperty(PID_TTL, true, PDT_UNSIGNED_CHAR, 1, ReadLv3 | WriteLv3, (uint8_t)16),
        new CallbackProperty<IpParameterObject>(this, PID_KNXNETIP_DEVICE_CAPABILITIES, false, PDT_BITSET16, 1, ReadLv3 | WriteLv0,
            [](IpParameterObject* io, uint16_t start, uint8_t count, uint8_t* data) -> uint8_t 
            { 
                if(start == 0)
                {
                    uint16_t currentNoOfElements = 1;
                    pushWord(currentNoOfElements, data);
                    return 1;
                }

                uint16_t capabilities = 0x1;
#ifdef KNX_TUNNELING
                capabilities |= 2;
#endif
#if MASK_VERSION == 0x091A
                capabilities |= 4;
#endif
#ifdef USE_IPSECURE
                capabilities |= 64;
#endif
                pushWord(capabilities, data);
                return 1;
            }),
#ifdef USE_IPSECURE
        new DataProperty(PID_BACKBONE_KEY, true, PDT_GENERIC_16, 1, ReadLv0 | WriteLv0),
        new DataProperty(PID_DEVICE_AUTHENTICATION, true, PDT_GENERIC_16, 1, ReadLv0 | WriteLv0),
        new DataProperty(PID_USER_PASSWORD_HASHES, true, PDT_GENERIC_16, 127, ReadLv0 | WriteLv0),
        new FunctionProperty<IpParameterObject>(this, PID_SECURED_SERVICE_FAMILIES,
            [](IpParameterObject* io, uint8_t* data, uint8_t length, uint8_t* result, uint8_t& capacity) {
                if (!result || capacity < 2) { capacity = 0; return; }
                result[0] = ReturnCodes::DataVoid; result[1] = data && length >= 2 ? data[1] : 0;
                capacity = 2;
                if (!data || length != 4 || data[0] != 0 || data[1] != 0 ||
                    data[2] < 3 || data[2] > 5 || data[3] > 1) return;
                const uint16_t bit = 1U << data[2];
                const uint16_t families = data[3] ? io->_secureServiceFamilies | bit : io->_secureServiceFamilies & ~bit;
                result[0] = io->secureServiceFamilies(families) ? ReturnCodes::Success : ReturnCodes::DataVoid;
            },
            [](IpParameterObject* io, uint8_t* data, uint8_t length, uint8_t* result, uint8_t& capacity) {
                if (!result || capacity < 2) { capacity = 0; return; }
                result[0] = ReturnCodes::DataVoid; result[1] = data && length >= 2 ? data[1] : 0;
                const uint8_t originalCapacity = capacity; capacity = 2;
                if (!data || length != 3 || data[0] != 0 || data[1] != 0 ||
                    data[2] < 3 || data[2] > 5 || originalCapacity < 4) return;
                result[0] = ReturnCodes::Success; result[2] = data[2];
                result[3] = (io->_secureServiceFamilies & (1U << data[2])) ? 1 : 0; capacity = 4;
            }),
        new DataProperty(PID_MULTICAST_LATENCY_TOLERANCE, true, PDT_UNSIGNED_INT, 1, ReadLv3 | WriteLv0, (uint16_t)2000),
        new DataProperty(PID_SYNC_LATENCY_FRACTION, true, PDT_SCALING, 1, ReadLv3 | WriteLv0, (uint8_t)26),
        new DataProperty(PID_TUNNELING_USERS, true, PDT_GENERIC_02,
#ifdef KNX_TUNNELING
                         126 * KNX_TUNNELING,
#else
                         126,
#endif
                         ReadLv0 | WriteLv0),
#endif
        new DataProperty(PID_FRIENDLY_NAME, true, PDT_UNSIGNED_CHAR, 30, ReadLv3 | WriteLv3)
    };
    initializeProperties(sizeof(properties), properties);
}

static void resetArray(Property* property)
{
    if (property == nullptr)
        return;

    // DataProperty's start-index-zero write is the canonical array reset: it
    // clears both storage and currentElements. Writing zero into every slot
    // instead leaves the array at MaxElements and makes 0.0.0/custom tunnel
    // records look configured after a factory reset.
    const uint8_t noElements[2] = {0, 0};
    property->write(0, 1, noElements);
}

static void resetScalar(Property* property, uint32_t value)
{
    if (property == nullptr)
        return;

    switch (property->ElementSize())
    {
        case 1:
            property->write((uint8_t)value);
            break;
        case 2:
            property->write((uint16_t)value);
            break;
        case 4:
            property->write(value);
            break;
        default:
            break;
    }
}

void IpParameterObject::masterReset(EraseCode eraseCode, uint8_t channel)
{
    (void)channel;
    if (eraseCode != EraseCode::FactoryReset &&
        eraseCode != EraseCode::FactoryResetWithoutIA)
        return;

    resetScalar(property(PID_PROJECT_INSTALLATION_ID), 0);
    resetScalar(property(PID_IP_ASSIGNMENT_METHOD), 0);
    resetScalar(property(PID_IP_ADDRESS), 0);
    resetScalar(property(PID_SUBNET_MASK), 0);
    resetScalar(property(PID_DEFAULT_GATEWAY), 0);
    resetScalar(property(PID_ROUTING_MULTICAST_ADDRESS), DEFAULT_MULTICAST_ADDR);
    resetScalar(property(PID_TTL), 16);
    resetArray(property(PID_FRIENDLY_NAME));
#ifdef USE_IPSECURE
    _secureServiceFamilies = 0;
    resetArray(property(PID_BACKBONE_KEY));
    resetArray(property(PID_DEVICE_AUTHENTICATION));
    resetArray(property(PID_USER_PASSWORD_HASHES));
    resetArray(property(PID_TUNNELING_USERS));
    resetScalar(property(PID_MULTICAST_LATENCY_TOLERANCE), 2000);
    resetScalar(property(PID_SYNC_LATENCY_FRACTION), 26);
#endif
#ifdef KNX_TUNNELING
    resetArray(property(PID_ADDITIONAL_INDIVIDUAL_ADDRESSES));
    resetArray(property(PID_CUSTOM_RESERVED_TUNNELS_CTRL));
    resetArray(property(PID_CUSTOM_RESERVED_TUNNELS_IP));
#endif
}

#ifdef USE_IPSECURE
bool IpParameterObject::securitySerialNumber(uint8_t output[6]) const
{
    if (!output) return false;
    memset(output, 0, 6);
    Property* property = _deviceObject.property(PID_SERIAL_NUMBER);
    if (!property || property->read(output) != 1) return false;
    const uint8_t zero[6] = {};
    const uint8_t developmentSerial[6] = {0x00,0xfa,0x01,0x02,0x03,0x04};
    // The default DeviceObject serial is shared by every unprovisioned stack.
    // Using it under a common backbone key would repeat multicast CTR nonces.
    return memcmp(output, zero, 6) && memcmp(output, developmentSerial, 6);
}
bool IpParameterObject::secureServiceFamilies(uint16_t value)
{
    const uint16_t supported = (1U << 3) | (1U << 4) | (1U << 5);
    if ((value & ~supported) || ((value & (1U << 4)) && !(value & (1U << 3)))) return false;
    _secureServiceFamilies = value; return true;
}
bool IpParameterObject::tunnelingUser(uint16_t user, uint8_t tunnelingAddressIndex)
{
    if (user == 1) return true;
    if (user < 2 || user > 127) return false;
#ifndef KNX_TUNNELING
    (void)tunnelingAddressIndex;
    return false;
#else
    if (tunnelingAddressIndex > KNX_TUNNELING) return false;
    uint16_t count = 0; readPropertyLength(PID_TUNNELING_USERS, count);
    const uint8_t* entries = propertyData(PID_TUNNELING_USERS);
    uint16_t previous = 0; bool allowed = false;
    for (uint16_t i = 0; entries && i < count; ++i)
    {
        const uint8_t* entry = entries + 2U * i;
        const uint16_t tuple = getWord(entry);
        if (entry[0] < 2 || entry[0] > 127 || !entry[1] || entry[1] > KNX_TUNNELING || tuple < previous) return false;
        previous = tuple;
        if (entry[0] == user && (!tunnelingAddressIndex || entry[1] == tunnelingAddressIndex)) allowed = true;
    }
    return allowed;
#endif
}
uint8_t* IpParameterObject::save(uint8_t* buffer)
{ return InterfaceObject::save(pushWord(_secureServiceFamilies, buffer)); }
const uint8_t* IpParameterObject::restore(const uint8_t* buffer)
{
    buffer = popWord(_secureServiceFamilies, buffer);
    if (_secureServiceFamilies & ~((1U << 3) | (1U << 4) | (1U << 5))) _secureServiceFamilies = 0xffff;
    return InterfaceObject::restore(buffer);
}
uint16_t IpParameterObject::saveSize() { return 2 + InterfaceObject::saveSize(); }
#endif

#endif
