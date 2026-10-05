#pragma once

#include "config.h"
#include "bau_systemB.h"
#include "device_object.h"
#include "security_interface_object.h"
#include "application_program_object.h"
#include "router_object.h"
#include "application_layer.h"
#include "secure_application_layer.h"
#include "transport_layer.h"
#include "network_layer_coupler.h"
#include "data_link_layer.h"
#include "platform.h"
#include "memory.h"

class BauSystemBCoupler : public BauSystemB
{
  public:
    BauSystemBCoupler(Platform& platform);
    void loop() override;
    bool configured() override;
    bool localManagementIndication(APDU& request, bool connected,
                                  void (*respond)(void*, APDU&), void* context) override
    {
#ifdef USE_DATASECURE
        return _appLayer.localManagementIndication(request, connected, respond, context);
#else
        return BauSystemB::localManagementIndication(request, connected, respond, context);
#endif
    }
#ifdef USE_DATASECURE
    bool configureSecureProxy(const SecureProxyRule* rules, uint16_t count) { return _secureProxy.configure(rules, count); }
    void securityProxyDecoder(SecureProxyDecoder decoder) { _netLayer.securityProxyDecoder(decoder); }
    bool allowTemporaryRoute(uint16_t source, uint16_t destination, uint8_t sourceInterface, uint32_t durationMs)
    { return _secureProxy.allowTemporaryRoute(source, destination, sourceInterface, durationMs); }
#endif

  protected:
    ApplicationLayer& applicationLayer() override;

    void doMasterReset(EraseCode eraseCode, uint8_t channel) override;

    Platform& _platform;

#ifdef USE_DATASECURE
    SecureApplicationLayer _appLayer;
    SecurityInterfaceObject _secIfObj;
    SecureProxy _secureProxy;
#else
    ApplicationLayer _appLayer;
#endif
    TransportLayer _transLayer;
    NetworkLayerCoupler _netLayer;
    bool _configured = true;
};
