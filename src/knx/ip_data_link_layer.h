#pragma once

#include "config.h"
#ifdef USE_IP

#include <stdint.h>
#include "data_link_layer.h"
#include "ip_parameter_object.h"
#include "service_families.h"
#include "ip_tunnel_server.h"
#ifdef USE_IPSECURE
#include "ip_secure.h"
#endif

class IpDataLinkLayer : public DataLinkLayer
#ifdef KNX_TUNNELING
    , public IpDiscoveryHandler
#endif
{
    using DataLinkLayer::_deviceObject;

  public:
    IpDataLinkLayer(DeviceObject& devObj, IpParameterObject& ipParam,
                    NetworkLayerEntity& netLayerEntity,
                    Platform& platform, BusAccessUnit& busAccessUnit,
#ifdef KNX_TUNNELING
                    IpTunnelServer& ipTunnelServer,
#endif
                    DataLinkLayerCallbacks* dllcb = nullptr);

    void loop();
    void enabled(bool value);
    bool enabled() const;
    DptMedium mediumType() const override;
    void handleSearchRequest(uint8_t* packet, uint16_t length,
                             uint32_t address, uint16_t port, bool tcp = false)
#ifdef KNX_TUNNELING
                             override
#endif
                             ;


  private:
    bool _enabled = false;
    uint8_t _frameCount[10] = {0,0,0,0,0,0,0,0,0,0};
    uint8_t _frameCountBase = 0;
    uint32_t _frameCountTimeBase = 0;
    bool sendFrame(CemiFrame& frame);

#if KNX_SERVICE_FAMILY_CORE >= 2
    void loopHandleSearchRequestExtended(uint8_t* buffer, uint16_t length,
                                         uint32_t remoteAddr, uint16_t remotePort, bool tcp = false);
#endif
    void sendSearchResponse(uint32_t address, uint16_t port, uint8_t* packet, uint16_t length);
    bool sendBytes(uint8_t* buffer, uint16_t length);
    bool isSendLimitReached();

    IpParameterObject& _ipParameters;
#ifdef USE_IPSECURE
    IpSecureRouting _secureRouting;
    uint32_t _multicastAddress = 0;
    void updateMulticast();
#endif
    DataLinkLayerCallbacks* _dllcb;
};
#endif
