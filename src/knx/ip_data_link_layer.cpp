#include "config.h"
#ifdef USE_IP

#include "ip_data_link_layer.h"

#include "bits.h"
#include "platform.h"
#include "device_object.h"
#include "knx_ip_routing_indication.h"
#include "knx_ip_search_request.h"
#include "knx_ip_search_response.h"
#include "knx_ip_search_request_extended.h"
#include "knx_ip_search_response_extended.h"

#include <stdio.h>
#include <string.h>

#define KNXIP_HEADER_LEN 0x6
#define KNXIP_PROTOCOL_VERSION 0x10

#define MIN_LEN_CEMI 10

namespace
{
bool validKnxIpDatagram(const uint8_t* buffer, uint16_t length)
{
    return buffer != nullptr && length >= KNXIP_HEADER_LEN &&
           buffer[0] == KNXIP_HEADER_LEN &&
           buffer[1] == KNXIP_PROTOCOL_VERSION &&
           getWord(buffer + 4) == length;
}

bool validSearchHpai(const uint8_t* buffer, uint16_t length, uint32_t remoteAddr, bool tcp = false)
{
    if (buffer == nullptr || length < KNXIP_HEADER_LEN + LEN_IPHPAI)
        return false;

    const uint16_t hpaiOffset = KNXIP_HEADER_LEN;
    const uint32_t claimedAddress = getInt(buffer + hpaiOffset + 2);
    return buffer[hpaiOffset] == LEN_IPHPAI &&
           buffer[hpaiOffset + 1] == (uint8_t)(tcp ? IPV4_TCP : IPV4_UDP) &&
           (claimedAddress == 0 || claimedAddress == remoteAddr) &&
           (!tcp || (claimedAddress == 0 && getWord(buffer + hpaiOffset + 6) == 0));
}
}

IpDataLinkLayer::IpDataLinkLayer(DeviceObject& devObj, IpParameterObject& ipParam,
                                 NetworkLayerEntity &netLayerEntity,
                                 Platform& platform, BusAccessUnit& busAccessUnit,
#ifdef KNX_TUNNELING
                                IpTunnelServer& ipTunnelServer,
#endif
                                 DataLinkLayerCallbacks* dllcb) : DataLinkLayer(devObj, netLayerEntity, platform, busAccessUnit
#ifdef KNX_TUNNELING
                                                                                    , ipTunnelServer
#endif
                                ),
                                 _ipParameters(ipParam),
#ifdef USE_IPSECURE
                                 _secureRouting(platform, ipParam),
#endif
                                 _dllcb(dllcb)
{
}

bool IpDataLinkLayer::sendFrame(CemiFrame& frame)
{
    if (!frame.valid())
    {
        dataConReceived(frame, false);
        return false;
    }

    KnxIpRoutingIndication packet(frame);
    // only send 50 packet per second: see KNX 3.2.6 p.6
    if(isSendLimitReached())
    {
        // Complete the data-link request even when local rate limiting drops
        // the packet; otherwise the upper layer waits forever for a con.
        dataConReceived(frame, false);
        return false;
    }
    bool success = sendBytes(packet.data(), packet.totalLength());
#ifdef KNX_ACTIVITYCALLBACK
    if(_dllcb)
        _dllcb->activity((_netIndex << KNX_ACTIVITYCALLBACK_NET) | (KNX_ACTIVITYCALLBACK_DIR_SEND << KNX_ACTIVITYCALLBACK_DIR));
#endif
    dataConReceived(frame, success);
    return success;
}



void IpDataLinkLayer::loop()
{
    if (!_enabled)
        return;

#ifdef USE_IPSECURE
    updateMulticast();
    _secureRouting.loop();
#endif

    uint8_t buffer[512];
    uint16_t remotePort = 0;
    uint32_t remoteAddr = 0;
    int len = _platform.readBytesMultiCast(buffer, 512, remoteAddr, remotePort);
    if (len <= 0)
        return;

    if (!validKnxIpDatagram(buffer, (uint16_t)len))
        return;

#ifdef USE_IPSECURE
    const uint16_t outerService = getWord(buffer + 2);
    if (outerService == KnxIpSecure::TimerNotify ||
        (outerService == KnxIpSecure::Wrapper && len >= 44 && getWord(buffer + 6) == 0))
    {
        if (!_secureRouting.required()) return;
        len = _secureRouting.receive(buffer, len);
        if (!len) return;
    }
    else if (outerService >= 0x0530 && outerService <= 0x0533 && _secureRouting.required()) return;
#endif

#ifdef KNX_ACTIVITYCALLBACK
    if(_dllcb)
        _dllcb->activity((_netIndex << KNX_ACTIVITYCALLBACK_NET) | (KNX_ACTIVITYCALLBACK_DIR_RECV << KNX_ACTIVITYCALLBACK_DIR));
#endif

    uint16_t code;
    popWord(code, buffer + 2);
    switch ((KnxIpServiceType)code)
    {
        case RoutingIndication:
        {
            const uint16_t cemiLength = (uint16_t)len - KNXIP_HEADER_LEN;
            if (cemiLength < MIN_LEN_CEMI ||
                (MessageCode)buffer[KNXIP_HEADER_LEN] != L_data_ind ||
                !CemiFrame::validBuffer(buffer + KNXIP_HEADER_LEN, cemiLength))
                break;

            KnxIpRoutingIndication routingIndication(buffer, len);
            if (routingIndication.frame().valid())
                frameReceived(routingIndication.frame());
            break;
        }
        
        case SearchRequest:
        {
            handleSearchRequest(buffer, len, remoteAddr, remotePort);
            break;
        }
        case SearchRequestExt:
        {
            handleSearchRequest(buffer, len, remoteAddr, remotePort);
            break;
        }
        default:
        {
#ifdef KNX_TUNNELING
            if(!_ipTunnelServer.HandleIpFrame(buffer, len, remoteAddr, remotePort))
#endif
            {
                print("Unhandled KNX-IP service identifier: ");
                println(code, HEX);
            }
            break;
        }

    }
}

void IpDataLinkLayer::handleSearchRequest(uint8_t* buffer, uint16_t length,
                                          uint32_t remoteAddr, uint16_t remotePort, bool tcp)
{
    if (!validKnxIpDatagram(buffer, length) || !validSearchHpai(buffer, length, remoteAddr, tcp)) return;
    if (getWord(buffer + 2) == SearchRequest)
    {
        if (tcp) return; // Legacy search is discovery-endpoint UDP only.
        if (length != KNXIP_HEADER_LEN + LEN_IPHPAI) return;
        KnxIpSearchRequest searchRequest(buffer, length);
        KnxIpSearchResponse searchResponse(_ipParameters, _deviceObject);
        if (tcp)
        {
            searchResponse.controlEndpoint().code(IPV4_TCP);
            searchResponse.controlEndpoint().ipAddress(0);
            searchResponse.controlEndpoint().ipPortNumber(0);
        }
        const uint16_t responsePort = searchRequest.hpai().ipPortNumber() ? searchRequest.hpai().ipPortNumber() : remotePort;
        sendSearchResponse(remoteAddr, responsePort, searchResponse.data(), searchResponse.totalLength());
    }
#if KNX_SERVICE_FAMILY_CORE >= 2
    else if (getWord(buffer + 2) == SearchRequestExt)
        loopHandleSearchRequestExtended(buffer, length, remoteAddr, remotePort, tcp);
#endif
}

void IpDataLinkLayer::sendSearchResponse(uint32_t address, uint16_t port, uint8_t* packet, uint16_t length)
{
#ifdef KNX_ACTIVITYCALLBACK
    if (_dllcb) _dllcb->activity((_netIndex << KNX_ACTIVITYCALLBACK_NET) | (KNX_ACTIVITYCALLBACK_DIR_SEND << KNX_ACTIVITYCALLBACK_DIR) | KNX_ACTIVITYCALLBACK_IPUNICAST);
#endif
#ifdef KNX_TUNNELING
    _ipTunnelServer.sendDiscoveryResponse(address, port, packet, length);
#else
    _platform.sendBytesUniCast(address, port, packet, length);
#endif
}

#if KNX_SERVICE_FAMILY_CORE >= 2
void IpDataLinkLayer::loopHandleSearchRequestExtended(uint8_t* buffer, uint16_t length,
                                                      uint32_t remoteAddr, uint16_t remotePort, bool tcp)
{
    KnxIpSearchRequestExtended searchRequest(buffer, length);
    if (!searchRequest.valid())
        return;

    if(searchRequest.srpByProgMode)
    {
        println("srpByProgMode");
        if(!_deviceObject.progMode()) return;
    }

    if(searchRequest.srpByMacAddr)
    {
        println("srpByMacAddr");
        Property* macProperty = _ipParameters.property(PID_MAC_ADDRESS);
        if (macProperty == nullptr)
            return;
        uint8_t localMac[6] = {0};
        if (macProperty->read(localMac) == 0)
            return;
        for(int i = 0; i<6;i++)
            if(searchRequest.srpMacAddr[i] != localMac[i])
                return;
    }

#define LEN_SERVICE_DIB KNX_IP_EXT_SERVICE_DIB_LENGTH

    //defaults: "Device Information DIB", "Extended Device Information DIB" and "Supported Services DIB".
    uint32_t dibLength = LEN_DEVICE_INFORMATION_DIB + LEN_SERVICE_DIB + LEN_EXTENDED_DEVICE_INFORMATION_DIB;
#ifdef USE_IPSECURE
    dibLength += _ipParameters.securedServiceDibLength();
#endif

    if(searchRequest.srpByService)
    {
        println("srpByService");
        uint8_t length = searchRequest.srpServiceFamilies[0];
        uint8_t *currentPos = searchRequest.srpServiceFamilies + 2;
        for(int i = 0; i < (length-2)/2; i++)
        {
            uint8_t serviceFamily = (currentPos + i*2)[0];
            uint8_t version = (currentPos + i*2)[1];
            switch(serviceFamily)
            {
                case Core:
                    if(version > KNX_SERVICE_FAMILY_CORE) return;
                    break;
                case DeviceManagement:
                    if(version > KNX_SERVICE_FAMILY_DEVICE_MANAGEMENT) return;
                    break;
                case Tunnelling:
                    if(version > KNX_SERVICE_FAMILY_TUNNELING) return;
                    break;
                case Routing:
                    if(version > KNX_SERVICE_FAMILY_ROUTING) return;
                    break;
#ifdef USE_IPSECURE
                case Security:
                    if(version > 1) return;
                    break;
#endif
                default:
                    return; // An unsupported family cannot satisfy this SRP.
            }
        }
    }

    if(searchRequest.srpRequestDIBs)
    {
        //println("srpRequestDIBs");
        if(searchRequest.requestedDIB(IP_CONFIG))
            dibLength += LEN_IP_CONFIG_DIB; //16

        if(searchRequest.requestedDIB(IP_CUR_CONFIG))
            dibLength += LEN_IP_CURRENT_CONFIG_DIB; //20

        if(searchRequest.requestedDIB(KNX_ADDRESSES))
        {
            uint16_t length = 0;
            _ipParameters.readPropertyLength(PID_ADDITIONAL_INDIVIDUAL_ADDRESSES, length);
            const uint8_t* addresses = length > 0 ?
                                           _ipParameters.propertyData(PID_ADDITIONAL_INDIVIDUAL_ADDRESSES) : nullptr;
            const uint16_t addressCount = addresses != nullptr ? length : 0;
            dibLength += 4U + (uint32_t)addressCount * 2U;
        }

        if(searchRequest.requestedDIB(MANUFACTURER_DATA))
            dibLength += 0; //4 + n

#ifdef KNX_TUNNELING
        if(searchRequest.requestedDIB(TUNNELING_INFO))
        {
            uint16_t length = 0;
            _ipParameters.readPropertyLength(PID_ADDITIONAL_INDIVIDUAL_ADDRESSES, length);
            const uint8_t* addresses = length == KNX_TUNNELING ?
                                           _ipParameters.propertyData(PID_ADDITIONAL_INDIVIDUAL_ADDRESSES) : nullptr;
            const uint16_t addressCount = addresses != nullptr ? length : KNX_TUNNELING;
            dibLength += 4U + (uint32_t)addressCount * 4U;
        }
#endif
    }

    uint32_t maxDibLength = 500U - LEN_KNXIP_HEADER - LEN_IPHPAI;
#ifdef KNX_TUNNELING
    maxDibLength = _ipTunnelServer.discoveryResponseLimit() - LEN_KNXIP_HEADER - LEN_IPHPAI;
#endif
    if (dibLength > maxDibLength)
    {
        printf("skipped response DIB length > %lu. Length: %lu bytes\n",
               (unsigned long)maxDibLength, (unsigned long)dibLength);
        return;
    }

    KnxIpSearchResponseExtended searchResponse(_ipParameters, _deviceObject, (int)dibLength);
    if (tcp)
    {
        searchResponse.controlEndpoint().code(IPV4_TCP);
        searchResponse.controlEndpoint().ipAddress(0);
        searchResponse.controlEndpoint().ipPortNumber(0);
    }

    searchResponse.setDeviceInfo(_ipParameters, _deviceObject); //DescriptionTypeCode::DeviceInfo 1
    searchResponse.setSupportedServices(); //DescriptionTypeCode::SUPP_SVC_FAMILIES 2
    searchResponse.setExtendedDeviceInfo(); //DescriptionTypeCode::EXTENDED_DEVICE_INFO 8
#ifdef USE_IPSECURE
    searchResponse.setSecuredServices(_ipParameters);
#endif

    if(searchRequest.srpRequestDIBs)
    {
        if(searchRequest.requestedDIB(IP_CONFIG))
            searchResponse.setIpConfig(_ipParameters);

        if(searchRequest.requestedDIB(IP_CUR_CONFIG))
            searchResponse.setIpCurrentConfig(_ipParameters);

        if(searchRequest.requestedDIB(KNX_ADDRESSES))
            searchResponse.setKnxAddresses(_ipParameters, _deviceObject);

        if(searchRequest.requestedDIB(MANUFACTURER_DATA))
        {
            //println("requested MANUFACTURER_DATA but not implemented");
        }

#ifdef KNX_TUNNELING
        if(searchRequest.requestedDIB(TUNNELING_INFO))
            searchResponse.setTunnelingInfo(_ipParameters, _deviceObject,
                                            _ipTunnelServer.tunnelConnections(), _ipTunnelServer.discoveryUser());
#endif
    }

    if(searchResponse.totalLength() > 500)
    {
        printf("skipped response length > 500. Length: %d bytes\n", searchResponse.totalLength());
        return;
    }

    const uint16_t responsePort = searchRequest.hpai().ipPortNumber() ?
                                      searchRequest.hpai().ipPortNumber() : remotePort;
    sendSearchResponse(remoteAddr, responsePort, searchResponse.data(), searchResponse.totalLength());
}
#endif



void IpDataLinkLayer::enabled(bool value)
{
//    _print("own address: ");
//    _println(_deviceObject.individualAddress());
    if (value && !_enabled)
    {
#ifdef KNX_TUNNELING
        // Register only after the BAU has constructed all of its members.
        // In Bau091A the data-link layer precedes the tunnel server.
        _ipTunnelServer.discoveryHandler(this);
#endif
        _platform.setupMultiCast(_ipParameters.propertyValue<uint32_t>(PID_ROUTING_MULTICAST_ADDRESS), KNXIP_MULTICAST_PORT);
#ifdef USE_IPSECURE
        _multicastAddress = _ipParameters.propertyValue<uint32_t>(PID_ROUTING_MULTICAST_ADDRESS);
        _secureRouting.enabled(true);
#endif
#if defined(KNX_TUNNELING) && defined(USE_IPSECURE)
        _ipTunnelServer.secureEnabled(true);
#endif
        _enabled = true;
        return;
    }

    if(!value && _enabled)
    {
#ifdef KNX_TUNNELING
        _ipTunnelServer.discoveryHandler(nullptr);
#endif
        _platform.closeMultiCast();
#ifdef USE_IPSECURE
        _secureRouting.enabled(false);
#endif
#if defined(KNX_TUNNELING) && defined(USE_IPSECURE)
        _ipTunnelServer.secureEnabled(false);
#endif
        _enabled = false;
        return;
    }
}

bool IpDataLinkLayer::enabled() const
{
    return _enabled;
}

DptMedium IpDataLinkLayer::mediumType() const
{
    return DptMedium::KNX_IP;
}

bool IpDataLinkLayer::sendBytes(uint8_t* bytes, uint16_t length)
{
    if (!_enabled)
        return false;

#ifdef USE_IPSECURE
    updateMulticast();
    if (_secureRouting.required()) return _secureRouting.send(bytes, length);
#endif

    return _platform.sendBytesMultiCast(bytes, length);
}

#ifdef USE_IPSECURE
void IpDataLinkLayer::updateMulticast()
{
    const uint32_t address = _ipParameters.propertyValue<uint32_t>(PID_ROUTING_MULTICAST_ADDRESS);
    if (address == _multicastAddress) return;
    _platform.closeMultiCast();
    _platform.setupMultiCast(address, KNXIP_MULTICAST_PORT);
    _multicastAddress = address;
}
#endif

bool IpDataLinkLayer::isSendLimitReached()
{
    uint32_t curTime = millis() / 100;

    // check if the countbuffer must be adjusted
    if(curTime >= _frameCountTimeBase)
    {
        uint32_t timeBaseDiff = curTime - _frameCountTimeBase;
        if(timeBaseDiff > 10)
            timeBaseDiff = 10;
        for(int i = 0; i < timeBaseDiff ; i++)
        {
            _frameCountBase++;
            _frameCountBase = _frameCountBase % 10;
            _frameCount[_frameCountBase] = 0;
        }
        _frameCountTimeBase = curTime;
    }
    else // curTime < _frameCountTimeBase => millis overflow, reset
    {
        for(int i = 0; i < 10 ; i++)
            _frameCount[i] = 0;
        _frameCountBase = 0;
        _frameCountTimeBase = curTime;
    }

    //check if we are over the limit
    uint16_t sum = 0;
    for(int i = 0; i < 10 ; i++)
        sum += _frameCount[i];
    if(sum >= 50)
    {
        println("Dropping packet due to 50p/s limit");
        return true;   // drop packet
    }
    else
    {
        _frameCount[_frameCountBase]++;
        //print("sent packages in last 1000ms: ");
        //print(sum);
        //print(" curTime: ");
        //println(curTime);
        return false;
    }
}
#endif
