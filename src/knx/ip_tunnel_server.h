#pragma once

#include "config.h"
#ifdef KNX_TUNNELING
#ifndef KNX_TUNNELING_DEVMGMT
#define KNX_TUNNELING_DEVMGMT 1
#endif

#include <stdint.h>
#include "knx_types.h"
#include "knx_ip_tunnel_connection.h"
#include "cemi_frame.h"
#include "ip_parameter_object.h"
#ifdef USE_IPSECURE
#include "ip_secure.h"
#endif

class CemiServer;

// Discovery is shared by multicast UDP and authenticated unicast sessions.
// The synchronous responder must preserve the currently dispatching session.
class IpDiscoveryHandler
{
  public:
    virtual ~IpDiscoveryHandler() = default;
    virtual void handleSearchRequest(uint8_t* packet, uint16_t length,
                                    uint32_t address, uint16_t port, bool tcp) = 0;
};

class IpTunnelServer
#ifdef USE_IPSECURE
    : public IpSecureSessionHandler
#endif
{
  public:
    /**
     * The constructor.
     * @param bau methods are called here depending of the content of the APDU
     */
    IpTunnelServer(DeviceObject& devObj, IpParameterObject& ipParam, Platform& platform, CemiServer& cemiServer);

    void loop();
    void dataRequestToChannelId(CemiFrame& frame, uint8_t channelId);
    void dataRequestToTunnel(CemiFrame& frame);
    void dataConfirmationToTunnel(CemiFrame& frame);
    void dataIndicationToTunnel(CemiFrame& frame);
    bool isTunnelAddress(uint16_t addr);
    bool isSentToTunnel(uint16_t address, bool isGrpAddr);
    /** True only for an active KNXnet/IP device-management channel. */
    bool isConfigChannel(uint8_t channelId) const;
    /** Mutable tunnel storage used only to encode the Core-v2 tunnelling-info DIB. */
    KnxIpTunnelConnection* tunnelConnections() { return tunnels; }
    bool HandleIpFrame(uint8_t* buffer, uint16_t length, uint32_t& src_addr, uint16_t& src_port);
    void discoveryHandler(IpDiscoveryHandler* handler) { _discoveryHandler = handler; }
    bool sendDiscoveryResponse(uint32_t address, uint16_t port, uint8_t* packet, uint16_t length)
    { return sendUnicast(address, port, packet, length); }
    uint16_t discoveryUser() const
    {
#ifdef USE_IPSECURE
        return _secureSessions.user(_dispatchSession);
#else
        return 0;
#endif
    }
    uint16_t discoveryResponseLimit() const
    {
#ifdef USE_IPSECURE
        if (_dispatchSession && KNX_IPSECURE_MAX_FRAME - KnxIpSecure::Overhead < 500)
            return KNX_IPSECURE_MAX_FRAME - KnxIpSecure::Overhead;
#endif
        return 500;
    }
#ifdef USE_IPSECURE
    void secureEnabled(bool value) { _secureSessions.enabled(value); }
    /** IP administrator authentication only; never implies SAL Tool AuthConf. */
    bool isSecureConfigChannel(uint8_t channel) const;
    void secureIpFrame(uint8_t* packet, uint16_t length, uint32_t address, uint16_t port, uint16_t session) override;
    void secureSessionClosed(uint16_t session) override;
#endif

  private:

    void sendFrameToTunnel(KnxIpTunnelConnection *tunnel, CemiFrame& frame);
    void HandleConnectRequest(uint8_t* buffer, uint16_t length, uint32_t& src_addr, uint16_t& src_port);
    void HandleConnectionStateRequest(uint8_t* buffer, uint16_t length, uint32_t src_addr, uint16_t src_port);
    void HandleDisconnectRequest(uint8_t* buffer, uint16_t length, uint32_t src_addr, uint16_t src_port);
    void HandleDescriptionRequest(uint8_t* buffer, uint16_t length, uint32_t src_addr, uint16_t src_port);
    void HandleDeviceConfigurationRequest(uint8_t* buffer, uint16_t length, uint32_t src_addr, uint16_t src_port);
    void HandleTunnelingRequest(uint8_t* buffer, uint16_t length, uint32_t src_addr, uint16_t src_port);
    void HandleTunnelAcknowledgement(uint8_t* buffer, uint16_t length, uint32_t src_addr, uint16_t src_port, bool configChannel);
    bool sendUnicast(uint32_t address, uint16_t port, uint8_t* packet, uint16_t length);
    bool sendToTunnel(KnxIpTunnelConnection& tunnel, bool control, uint8_t* packet, uint16_t length);
    bool matchesEndpoint(const KnxIpTunnelConnection* tunnel, uint32_t address, uint16_t port, bool control) const;
#ifdef USE_IPSECURE
    bool channelAuthorized(const KnxIpTunnelConnection& tunnel) const;
    IpSecureSessions _secureSessions;
    uint16_t _dispatchSession = 0;
#endif


    KnxIpTunnelConnection tunnels[KNX_TUNNELING+KNX_TUNNELING_DEVMGMT];
    uint8_t _lastChannelId = 0;
    IpParameterObject& _ipParameters;
    DeviceObject& _deviceObject;
    Platform& _platform;
    CemiServer& _cemiServer;
    IpDiscoveryHandler* _discoveryHandler = nullptr;
};


#endif
