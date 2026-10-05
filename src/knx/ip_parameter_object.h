#pragma once

#include "config.h"
#ifdef USE_IP
#include "interface_object.h"
#include "device_object.h"
#include "platform.h"

#define KNXIP_MULTICAST_PORT 3671

class IpParameterObject : public InterfaceObject
{
  public:
    IpParameterObject(DeviceObject& deviceObject, Platform& platform);
    void masterReset(EraseCode eraseCode, uint8_t channel) override;
#ifdef USE_IPSECURE
    uint16_t secureServiceFamilies() const { return _secureServiceFamilies; }
    bool secureServiceFamilies(uint16_t value);
    bool tunnelingUser(uint16_t user, uint8_t tunnelingAddressIndex = 0);
    /** KNX nonce identity; rejects unset/shared development serial numbers. */
    bool securitySerialNumber(uint8_t output[6]) const;
    uint8_t securedServiceDibLength() const
    {
        uint8_t count = 0;
        for (uint8_t family = 3; family <= 5; ++family) if (_secureServiceFamilies & (1U << family)) ++count;
        return count ? 2 + 2 * count : 0;
    }
    uint8_t* save(uint8_t* buffer) override;
    const uint8_t* restore(const uint8_t* buffer) override;
    uint16_t saveSize() override;
#endif

  private:
    DeviceObject& _deviceObject;
    Platform& _platform;
#ifdef USE_IPSECURE
    uint16_t _secureServiceFamilies = 0;
#endif
};
#endif
