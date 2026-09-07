#include "config.h"
#ifdef KNX_TUNNELING

#include "ip_tunnel_server.h"

#include "cemi_server.h"
#include "knx_ip_config_request.h"
#include "knx_ip_connect_request.h"
#include "knx_ip_connect_response.h"
#include "knx_ip_description_request.h"
#include "knx_ip_description_response.h"
#include "knx_ip_disconnect_request.h"
#include "knx_ip_disconnect_response.h"
#include "knx_ip_state_request.h"
#include "knx_ip_state_response.h"
#include "knx_ip_tunneling_ack.h"
#include "knx_ip_tunneling_request.h"

namespace
{
bool validKnxIpEnvelope(const uint8_t* buffer, uint16_t length)
{
    if (buffer == nullptr || length < LEN_KNXIP_HEADER)
        return false;

    return buffer[0] == LEN_KNXIP_HEADER &&
           buffer[1] == (uint8_t)KnxIp1_0 &&
           getWord(buffer + 4) == length;
}

bool validHpai(const uint8_t* buffer, uint16_t length, uint16_t offset)
{
    return buffer != nullptr && offset <= length &&
           length - offset >= LEN_IPHPAI &&
           buffer[offset] == LEN_IPHPAI &&
           buffer[offset + 1] == (uint8_t)IPV4_UDP;
}

bool hpaiAddressMatchesSource(const uint8_t* buffer, uint16_t offset, uint32_t srcAddr)
{
    const uint32_t claimedAddress = getInt(buffer + offset + 2);
    return claimedAddress == 0 || claimedAddress == srcAddr;
}

bool validConnectionHeader(const uint8_t* buffer, uint16_t length)
{
    return buffer != nullptr && length >= LEN_KNXIP_HEADER + LEN_CH &&
           buffer[LEN_KNXIP_HEADER] == LEN_CH;
}

bool validTunnelCemi(const uint8_t* buffer, uint16_t length)
{
    if (!validConnectionHeader(buffer, length) || length <= LEN_KNXIP_HEADER + LEN_CH)
        return false;

    const uint16_t cemiOffset = LEN_KNXIP_HEADER + LEN_CH;
    return CemiFrame::validBuffer(buffer + cemiOffset, length - cemiOffset);
}

bool validDeviceConfigurationCemi(const uint8_t* buffer, uint16_t length)
{
    if (!validTunnelCemi(buffer, length))
        return false;

    // A DeviceConfigurationRequest carries local-management cEMI requests,
    // never link-layer traffic or server-to-client confirmations/indications.
    switch ((MessageCode)buffer[LEN_KNXIP_HEADER + LEN_CH])
    {
        case M_PropRead_req:
        case M_PropWrite_req:
        case M_Reset_req:
            return true;
        default:
            return false;
    }
}

bool validTunnelingCemi(const uint8_t* buffer, uint16_t length)
{
    return validTunnelCemi(buffer, length) &&
           (MessageCode)buffer[LEN_KNXIP_HEADER + LEN_CH] == L_data_req;
}

bool endpointMatches(const KnxIpTunnelConnection* tunnel, uint32_t srcAddr, uint16_t srcPort, bool control)
{
    return tunnel != nullptr && tunnel->IpAddress == srcAddr &&
           (control ? tunnel->PortCtrl : tunnel->PortData) == srcPort;
}
}

IpTunnelServer::IpTunnelServer(DeviceObject& devObj, IpParameterObject& ipParam, Platform& platform, CemiServer& cemiServer) : _deviceObject(devObj),
                                                                                                                               _ipParameters(ipParam),
                                                                                                                               _platform(platform),
                                                                                                                               _cemiServer(cemiServer)
{
}

void IpTunnelServer::loop()
{
    for (int i = 0; i < KNX_TUNNELING + KNX_TUNNELING_DEVMGMT; i++)
    {
        if (tunnels[i].ChannelId != 0)
        {
            if (millis() - tunnels[i].lastHeartbeat > 120000)
            {
#ifdef KNX_LOG_TUNNELING
                print("Closed Tunnel 0x");
                print(tunnels[i].ChannelId, 16);
                println(" due to no heartbeat in 2 minutes");
#endif
                KnxIpDisconnectRequest discReq;
                discReq.channelId(tunnels[i].ChannelId);
                discReq.hpaiCtrl().length(LEN_IPHPAI);
                discReq.hpaiCtrl().code(IPV4_UDP);
                discReq.hpaiCtrl().ipAddress(tunnels[i].IpAddress);
                discReq.hpaiCtrl().ipPortNumber(tunnels[i].PortCtrl);
                _platform.sendBytesUniCast(tunnels[i].IpAddress, tunnels[i].PortCtrl, discReq.data(), discReq.totalLength());
                tunnels[i].Reset();
            }
        }
    }
}

void IpTunnelServer::dataRequestToChannelId(CemiFrame& frame, uint8_t channelId)
{
    KnxIpTunnelConnection* tun = nullptr;
    for (int i = 0; i < KNX_TUNNELING + KNX_TUNNELING_DEVMGMT; i++)
    {
#ifdef KNX_LOG_TUNNELING
        print("Tunnel ChannelId: ");
#endif
        if(tunnels[i].IsConfig)
        {
#ifdef KNX_LOG_TUNNELING
            print("Config ");
#endif
        }
#ifdef KNX_LOG_TUNNELING
        println(tunnels[i].ChannelId, 16);
#endif
        if (tunnels[i].ChannelId == channelId)
        {
            tun = &tunnels[i];
            break;
        }
    }

    if (tun == nullptr)
    {
#ifdef KNX_LOG_TUNNELING
        print("Found no Tunnel for ChannelId: ");
        println(channelId, 16);
#endif
        return;
    }

    sendFrameToTunnel(tun, frame);
}

void IpTunnelServer::dataRequestToTunnel(CemiFrame& frame)
{
    if (frame.addressType() == AddressType::GroupAddress)
    {
        for (int i = 0; i < KNX_TUNNELING; i++)
            if (tunnels[i].ChannelId != 0 && tunnels[i].IndividualAddress == frame.sourceAddress())
                sendFrameToTunnel(&tunnels[i], frame);
        // TODO check if source is from tunnel
        return;
    }

    KnxIpTunnelConnection* tun = nullptr;
    for (int i = 0; i < KNX_TUNNELING; i++)
    {
        if (tunnels[i].IndividualAddress == frame.sourceAddress())
            continue;

        if (tunnels[i].IndividualAddress == frame.destinationAddress())
        {
            tun = &tunnels[i];
            break;
        }
    }

    if (tun == nullptr)
    {
        for (int i = 0; i < KNX_TUNNELING; i++)
        {
            if (tunnels[i].IsConfig)
            {
#ifdef KNX_LOG_TUNNELING
                println("Found config Channel");
#endif
                tun = &tunnels[i];
                break;
            }
        }
    }

    if (tun == nullptr)
    {
#ifdef KNX_LOG_TUNNELING
        print("Found no Tunnel for IA: ");
        println(frame.destinationAddress(), 16);
#endif
        return;
    }

    sendFrameToTunnel(tun, frame);
}

void IpTunnelServer::dataConfirmationToTunnel(CemiFrame& frame)
{
    if (frame.addressType() == AddressType::GroupAddress)
    {
        for (int i = 0; i < KNX_TUNNELING; i++)
            if (tunnels[i].ChannelId != 0 && tunnels[i].IndividualAddress == frame.sourceAddress())
                sendFrameToTunnel(&tunnels[i], frame);
        // TODO check if source is from tunnel
        return;
    }

    KnxIpTunnelConnection* tun = nullptr;
    for (int i = 0; i < KNX_TUNNELING; i++)
    {
        if (tunnels[i].IndividualAddress == frame.destinationAddress())
            continue;

        if (tunnels[i].IndividualAddress == frame.sourceAddress())
        {
            tun = &tunnels[i];
            break;
        }
    }

    if (tun == nullptr)
    {
        for (int i = 0; i < KNX_TUNNELING; i++)
        {
            if (tunnels[i].IsConfig)
            {
#ifdef KNX_LOG_TUNNELING
                println("Found config Channel");
#endif
                tun = &tunnels[i];
                break;
            }
        }
    }

    if (tun == nullptr)
    {
#ifdef KNX_LOG_TUNNELING
        print("Found no Tunnel for IA: ");
        println(frame.destinationAddress(), 16);
#endif
        return;
    }

    sendFrameToTunnel(tun, frame);
}

void IpTunnelServer::dataIndicationToTunnel(CemiFrame& frame)
{
    if (frame.addressType() == AddressType::GroupAddress)
    {
        for (int i = 0; i < KNX_TUNNELING; i++)
            if (tunnels[i].ChannelId != 0 && tunnels[i].IndividualAddress != frame.sourceAddress())
                sendFrameToTunnel(&tunnels[i], frame);
        return;
    }

    KnxIpTunnelConnection* tun = nullptr;
    for (int i = 0; i < KNX_TUNNELING; i++)
    {
        if (tunnels[i].ChannelId == 0 || tunnels[i].IndividualAddress == frame.sourceAddress())
            continue;

        if (tunnels[i].IndividualAddress == frame.destinationAddress())
        {
            tun = &tunnels[i];
            break;
        }
    }

    if (tun == nullptr)
    {
        for (int i = 0; i < KNX_TUNNELING; i++)
        {
            if (tunnels[i].IsConfig)
            {
#ifdef KNX_LOG_TUNNELING
                println("Found config Channel");
#endif
                tun = &tunnels[i];
                break;
            }
        }
    }

    if (tun == nullptr)
    {
#ifdef KNX_LOG_TUNNELING
        print("Found no Tunnel for IA: ");
        println(frame.destinationAddress(), 16);
#endif
        return;
    }

    sendFrameToTunnel(tun, frame);
}

void IpTunnelServer::sendFrameToTunnel(KnxIpTunnelConnection* tunnel, CemiFrame& frame)
{
#ifdef KNX_LOG_TUNNELING
    print("Send to Channel: ");
    println(tunnel->ChannelId, 16);
#endif
    KnxIpTunnelingRequest req(frame);
    req.connectionHeader().sequenceCounter(tunnel->SequenceCounter_S++);
    req.connectionHeader().length(LEN_CH);
    req.connectionHeader().channelId(tunnel->ChannelId);

    if (frame.messageCode() != L_data_req && frame.messageCode() != L_data_con && frame.messageCode() != L_data_ind)
        req.serviceTypeIdentifier(DeviceConfigurationRequest);

    _platform.sendBytesUniCast(tunnel->IpAddress, tunnel->PortData, req.data(), req.totalLength());
}

bool IpTunnelServer::isTunnelAddress(uint16_t addr)
{
    if (addr == 0)
        return false; // 0.0.0 is not a valid tunnel address and is used as default value

    for (int i = 0; i < KNX_TUNNELING; i++)
        if (tunnels[i].IndividualAddress == addr)
            return true;

    return false;
}

bool IpTunnelServer::isConfigChannel(uint8_t channelId) const
{
    if (channelId == 0)
        return false;

    for (int i = 0; i < KNX_TUNNELING + KNX_TUNNELING_DEVMGMT; i++)
        if (tunnels[i].ChannelId == channelId)
            return tunnels[i].IsConfig;

    return false;
}

bool IpTunnelServer::isSentToTunnel(uint16_t address, bool isGrpAddr)
{
    if (isGrpAddr)
    {
        for (int i = 0; i < KNX_TUNNELING; i++)
            if (tunnels[i].ChannelId != 0)
                return true;
        return false;
    }
    else
    {
        for (int i = 0; i < KNX_TUNNELING; i++)
            if (tunnels[i].ChannelId != 0 && tunnels[i].IndividualAddress == address)
                return true;
        return false;
    }
}

bool IpTunnelServer::HandleIpFrame(uint8_t* buffer, uint16_t length, uint32_t& src_addr, uint16_t& src_port)
{
    if (!validKnxIpEnvelope(buffer, length))
        return false;

    uint16_t code;
    popWord(code, buffer + 2);
    switch ((KnxIpServiceType)code)
    {
        case ConnectRequest: {
            const uint16_t criOffset = LEN_KNXIP_HEADER + 2 * LEN_IPHPAI;
            if (length < criOffset + 2 ||
                !validHpai(buffer, length, LEN_KNXIP_HEADER) ||
                !validHpai(buffer, length, LEN_KNXIP_HEADER + LEN_IPHPAI) ||
                !hpaiAddressMatchesSource(buffer, LEN_KNXIP_HEADER, src_addr) ||
                !hpaiAddressMatchesSource(buffer, LEN_KNXIP_HEADER + LEN_IPHPAI, src_addr))
                break;

            const uint8_t criLength = buffer[criOffset];
            const ConnectionType connectionType = (ConnectionType)buffer[criOffset + 1];
            const bool knownLengthValid =
                (connectionType == TUNNEL_CONNECTION && criLength == LEN_CRI) ||
                (connectionType == DEVICE_MGMT_CONNECTION && criLength == 2);
            const bool unknownType = connectionType != TUNNEL_CONNECTION &&
                                     connectionType != DEVICE_MGMT_CONNECTION;
            if ((!knownLengthValid && !(unknownType && criLength >= 2)) ||
                (uint32_t)criOffset + criLength != length)
                break;

            HandleConnectRequest(buffer, length, src_addr, src_port);
            break;
        }

        case ConnectionStateRequest: {
            if (length != LEN_KNXIP_HEADER + 2 + LEN_IPHPAI ||
                !validHpai(buffer, length, LEN_KNXIP_HEADER + 2) ||
                !hpaiAddressMatchesSource(buffer, LEN_KNXIP_HEADER + 2, src_addr))
                break;
            HandleConnectionStateRequest(buffer, length, src_addr, src_port);
            break;
        }

        case DisconnectRequest: {
            if (length != LEN_KNXIP_HEADER + 2 + LEN_IPHPAI ||
                !validHpai(buffer, length, LEN_KNXIP_HEADER + 2) ||
                !hpaiAddressMatchesSource(buffer, LEN_KNXIP_HEADER + 2, src_addr))
                break;
            HandleDisconnectRequest(buffer, length, src_addr, src_port);
            break;
        }

        case DescriptionRequest: {
            if (length != LEN_KNXIP_HEADER + LEN_IPHPAI ||
                !validHpai(buffer, length, LEN_KNXIP_HEADER) ||
                !hpaiAddressMatchesSource(buffer, LEN_KNXIP_HEADER, src_addr))
                break;
            HandleDescriptionRequest(buffer, length, src_addr, src_port);
            break;
        }

        case DeviceConfigurationRequest: {
            if (!validDeviceConfigurationCemi(buffer, length))
                break;
            HandleDeviceConfigurationRequest(buffer, length, src_addr, src_port);
            break;
        }

        case TunnelingRequest: {
            if (!validTunnelingCemi(buffer, length))
                break;
            HandleTunnelingRequest(buffer, length, src_addr, src_port);
            break;
        }

        case DeviceConfigurationAck: {
            if (!validConnectionHeader(buffer, length) || length != LEN_KNXIP_HEADER + LEN_CH)
                break;
            HandleTunnelAcknowledgement(buffer, length, src_addr, src_port, true);
            break;
        }

        case TunnelingAck: {
            if (!validConnectionHeader(buffer, length) || length != LEN_KNXIP_HEADER + LEN_CH)
                break;
            HandleTunnelAcknowledgement(buffer, length, src_addr, src_port, false);
            break;
        }
        default:
            return false;
            break;
    }
    return true;
}

void IpTunnelServer::HandleConnectRequest(uint8_t* buffer, uint16_t length, uint32_t& src_addr, uint16_t& src_port)
{
    KnxIpConnectRequest connRequest(buffer, length);
    const uint16_t responsePort = connRequest.hpaiCtrl().ipPortNumber() ?
                                      connRequest.hpaiCtrl().ipPortNumber() : src_port;
#ifdef KNX_LOG_TUNNELING
    println("Got Connect Request!");
    switch (connRequest.cri().type())
    {
        case DEVICE_MGMT_CONNECTION:
            println("Device Management Connection");
            break;
        case TUNNEL_CONNECTION:
            println("Tunnel Connection");
            break;
        case REMLOG_CONNECTION:
            println("RemLog Connection");
            break;
        case REMCONF_CONNECTION:
            println("RemConf Connection");
            break;
        case OBJSVR_CONNECTION:
            println("ObjectServer Connection");
            break;
    }

    print("Data Endpoint: ");
    uint32_t ip = connRequest.hpaiData().ipAddress();
    print(ip >> 24);
    print(".");
    print((ip >> 16) & 0xFF);
    print(".");
    print((ip >> 8) & 0xFF);
    print(".");
    print(ip & 0xFF);
    print(":");
    println(connRequest.hpaiData().ipPortNumber());
    print("Ctrl Endpoint: ");
    ip = connRequest.hpaiCtrl().ipAddress();
    print(ip >> 24);
    print(".");
    print((ip >> 16) & 0xFF);
    print(".");
    print((ip >> 8) & 0xFF);
    print(".");
    print(ip & 0xFF);
    print(":");
    println(connRequest.hpaiCtrl().ipPortNumber());
#endif

    // We only support 0x03 and 0x04!
    if (connRequest.cri().type() != TUNNEL_CONNECTION && connRequest.cri().type() != DEVICE_MGMT_CONNECTION)
    {
#ifdef KNX_LOG_TUNNELING
        println("Only Tunnel/DeviceMgmt Connection ist supported!");
#endif
        KnxIpConnectResponse connRes(0x00, E_CONNECTION_TYPE);
        _platform.sendBytesUniCast(src_addr, responsePort, connRes.data(), connRes.totalLength());
        return;
    }

    if (connRequest.cri().type() == TUNNEL_CONNECTION && connRequest.cri().layer() != 0x02) // LinkLayer
    {
        // We only support 0x02!
#ifdef KNX_LOG_TUNNELING
        println("Only LinkLayer ist supported!");
#endif
        KnxIpConnectResponse connRes(0x00, E_TUNNELING_LAYER);
        _platform.sendBytesUniCast(src_addr, responsePort, connRes.data(), connRes.totalLength());
        return;
    }

    // data preparation

    // Bind the connection to the packet's actual source IP. Trusting a claimed
    // HPAI address lets a requester create a tunnel assigned to a third party.
    uint32_t srcIP = src_addr;
    uint16_t srcPort = connRequest.hpaiCtrl().ipPortNumber() ? connRequest.hpaiCtrl().ipPortNumber() : src_port;

    // read current elements in PID_ADDITIONAL_INDIVIDUAL_ADDRESSES
    uint16_t propCount = 0;
    _ipParameters.readPropertyLength(PID_ADDITIONAL_INDIVIDUAL_ADDRESSES, propCount);
    // Keep the generated fallback alive until the selected tunnel address is
    // consumed below.  A buffer declared in the else block would leave
    // `addresses` dangling as soon as that block ended.
    uint8_t fallbackAddresses[KNX_TUNNELING * 2] = {0};
    const uint8_t* addresses;
    if (propCount == KNX_TUNNELING)
    {
        addresses = _ipParameters.propertyData(PID_ADDITIONAL_INDIVIDUAL_ADDRESSES);
    }
    else // no tunnel PA configured, that means device is unconfigured and has 15.15.0
    {
        addresses = fallbackAddresses;
        for (int i = 0; i < KNX_TUNNELING; i++)
        {
            fallbackAddresses[i * 2 + 1] = i + 1;
            fallbackAddresses[i * 2] = _deviceObject.individualAddress() / 0x0100;
        }
        uint8_t count = KNX_TUNNELING;
        _ipParameters.writeProperty(PID_ADDITIONAL_INDIVIDUAL_ADDRESSES, 1, fallbackAddresses, count);
#ifdef KNX_LOG_TUNNELING
        println("no Tunnel-PAs configured, using own subnet");
#endif
    }

    _ipParameters.readPropertyLength(PID_CUSTOM_RESERVED_TUNNELS_CTRL, propCount);
    const uint8_t* tunCtrlBytes = nullptr;
    if (propCount == KNX_TUNNELING)
        tunCtrlBytes = _ipParameters.propertyData(PID_CUSTOM_RESERVED_TUNNELS_CTRL);

    _ipParameters.readPropertyLength(PID_CUSTOM_RESERVED_TUNNELS_IP, propCount);
    const uint8_t* tunCtrlIp = nullptr;
    if (propCount == KNX_TUNNELING)
        tunCtrlIp = _ipParameters.propertyData(PID_CUSTOM_RESERVED_TUNNELS_IP);

    bool resTunActive = (tunCtrlBytes && tunCtrlIp);
#ifdef KNX_LOG_TUNNELING
    if (resTunActive)
        println("Reserved Tunnel Feature active");

    if (tunCtrlBytes)
        printHex("tunCtrlBytes", tunCtrlBytes, KNX_TUNNELING);
    if (tunCtrlIp)
        printHex("tunCtrlIp", tunCtrlIp, KNX_TUNNELING * 4);
#endif

    uint8_t tunIdx = 0xff;
    if (connRequest.cri().type() == DEVICE_MGMT_CONNECTION)
    {
        for (int i = KNX_TUNNELING; i < KNX_TUNNELING + KNX_TUNNELING_DEVMGMT; i++)
        {
            if (tunnels[i].ChannelId == 0)
            {
                tunIdx = i;
                break;
            }
        }
        if (tunIdx == 0xff) 
            ; // Todo? tunIdx = 0xff => tun = null => E_NO_MORE_CONNECTIONS
    }
    else if (connRequest.cri().type() == TUNNEL_CONNECTION) //
    {
        // check if there is a reserved tunnel for the source
        int firstFreeTunnel = -1;
        int firstResAndFreeTunnel = -1;
        int firstResAndOccTunnel = -1;
        bool tunnelResActive[KNX_TUNNELING];
        uint8_t tunnelResOptions[KNX_TUNNELING];
        for (int i = 0; i < KNX_TUNNELING; i++)
        {
            if (resTunActive)
            {
                tunnelResActive[i] = *(tunCtrlBytes + i) & 0x80;
                tunnelResOptions[i] = (*(tunCtrlBytes + i) & 0x60) >> 5;
            }

            if (resTunActive && tunnelResActive[i]) // tunnel reserve feature active for this tunnel
            {
#ifdef KNX_LOG_TUNNELING
                print("tunnel reserve feature active for this tunnel: ");
                print(tunnelResActive[i]);
                print("  options: ");
                println(tunnelResOptions[i]);
#endif

                uint32_t rIP = 0;
                popInt(rIP, tunCtrlIp + 4 * i);
                if (srcIP == rIP)
                {
                    // reserved tunnel for this ip found
                    if (tunnels[i].ChannelId == 0) // check if it is free
                    {
                        if (firstResAndFreeTunnel < 0)
                            firstResAndFreeTunnel = i;
                    }
                    else
                    {
                        if (firstResAndOccTunnel < 0)
                            firstResAndOccTunnel = i;
                    }
                }
            }
            else
            {
                if (tunnels[i].ChannelId == 0 && firstFreeTunnel < 0)
                    firstFreeTunnel = i;
            }
        }
#ifdef KNX_LOG_TUNNELING
        print("firstFreeTunnel: ");
        print(firstFreeTunnel);
        print(" firstResAndFreeTunnel: ");
        print(firstResAndFreeTunnel);
        print(" firstResAndOccTunnel: ");
        println(firstResAndOccTunnel);
#endif

        if (resTunActive & (firstResAndFreeTunnel >= 0 || firstResAndOccTunnel >= 0)) // tunnel reserve feature active (for this src)
        {
            if (firstResAndFreeTunnel >= 0)
            {
                tunIdx = firstResAndFreeTunnel;
            }
            else if (firstResAndOccTunnel >= 0)
            {
                if (tunnelResOptions[firstResAndOccTunnel] == 1) // decline req
                {
                    ; // do nothing => decline
                }
                else if (tunnelResOptions[firstResAndOccTunnel] == 2) // close current tunnel connection on this tunnel and assign to this request
                {
                    KnxIpDisconnectRequest discReq;
                    discReq.channelId(tunnels[firstResAndOccTunnel].ChannelId);
                    discReq.hpaiCtrl().length(LEN_IPHPAI);
                    discReq.hpaiCtrl().code(IPV4_UDP);
                    discReq.hpaiCtrl().ipAddress(tunnels[firstResAndOccTunnel].IpAddress);
                    discReq.hpaiCtrl().ipPortNumber(tunnels[firstResAndOccTunnel].PortCtrl);
                    _platform.sendBytesUniCast(tunnels[firstResAndOccTunnel].IpAddress, tunnels[firstResAndOccTunnel].PortCtrl, discReq.data(), discReq.totalLength());
                    tunnels[firstResAndOccTunnel].Reset();

                    tunIdx = firstResAndOccTunnel;
                }
                else if (tunnelResOptions[firstResAndOccTunnel] == 3) // use the first unreserved tunnel (if one)
                {
                    if (firstFreeTunnel >= 0)
                        tunIdx = firstFreeTunnel;
                    else
                        ; // do nothing => decline
                }
                // else
                //  should not happen
                //  do nothing => decline
            }
            // else
            //  should not happen
            //  do nothing => decline
        }
        else
        {
            if (firstFreeTunnel >= 0)
                tunIdx = firstFreeTunnel;
            // else
            //  do nothing => decline
        }
    }

    KnxIpTunnelConnection* tun = nullptr;
    if (tunIdx != 0xFF)
    {
        tun = &tunnels[tunIdx];

        if (connRequest.cri().type() == DEVICE_MGMT_CONNECTION)
        {
            tun->IsConfig = true;
            tun->IndividualAddress = 0; // not relevant
        }
        else
        {
            tun->IsConfig = false;  // default
            uint16_t tunPa = 0;
            popWord(tunPa, addresses + (tunIdx * 2));

            // check if this PA is in use (should not happen, only when there is one pa wrongly assigned to more then one tunnel)
            for (int x = 0; x < KNX_TUNNELING; x++)
                if (tunnels[x].IndividualAddress == tunPa)
                {
#ifdef KNX_LOG_TUNNELING
                    println("cannot use tunnel because PA is already in use");
#endif
                    tunIdx = 0xFF;
                    tun = nullptr;
                    break;
                }
            if (tun)
                tun->IndividualAddress = tunPa;
        }
    }

    if (tun == nullptr)
    {
        println("no free tunnel availible");
        KnxIpConnectResponse connRes(0x00, E_NO_MORE_CONNECTIONS);
        _platform.sendBytesUniCast(src_addr, responsePort, connRes.data(), connRes.totalLength());
        return;
    }

    // the channel ID shall be unique on this tunnel server. catch the rare case of a double channel ID
    bool channelIdInUse;
    do
    {
        _lastChannelId++;
        channelIdInUse = false;
        for (int x = 0; x < KNX_TUNNELING + KNX_TUNNELING_DEVMGMT; x++)
            if (tunnels[x].ChannelId == _lastChannelId)
                channelIdInUse = true;
    } while (channelIdInUse);

    tun->ChannelId = _lastChannelId;
    tun->lastHeartbeat = millis();
    if (_lastChannelId == 255)
        _lastChannelId = 0;

    tun->IpAddress = srcIP;
    tun->PortData = connRequest.hpaiData().ipPortNumber() ? connRequest.hpaiData().ipPortNumber() : srcPort;
    tun->PortCtrl = connRequest.hpaiCtrl().ipPortNumber() ? connRequest.hpaiCtrl().ipPortNumber() : srcPort;

    print("New Tunnel-Connection[");
    print(tunIdx);
    print("], Channel: 0x");
    print(tun->ChannelId, 16);
    print(" PA: ");
    print(tun->IndividualAddress >> 12);
    print(".");
    print((tun->IndividualAddress >> 8) & 0xF);
    print(".");
    print(tun->IndividualAddress & 0xFF);

    print(" with ");
    print(tun->IpAddress >> 24);
    print(".");
    print((tun->IpAddress >> 16) & 0xFF);
    print(".");
    print((tun->IpAddress >> 8) & 0xFF);
    print(".");
    print(tun->IpAddress & 0xFF);
    print(":");
    print(tun->PortData);
    if (tun->PortData != tun->PortCtrl)
    {
        print(" (Ctrlport: ");
        print(tun->PortCtrl);
        print(")");
    }
    if (tun->IsConfig)
    {
        print(" (Config-Channel)");
    }
    println();

    KnxIpConnectResponse connRes(_ipParameters, tun->IndividualAddress, 3671, tun->ChannelId, connRequest.cri().type());
    _platform.sendBytesUniCast(tun->IpAddress, tun->PortCtrl, connRes.data(), connRes.totalLength());
}

void IpTunnelServer::HandleConnectionStateRequest(uint8_t* buffer, uint16_t length, uint32_t src_addr, uint16_t src_port)
{
    KnxIpStateRequest stateRequest(buffer, length);

    KnxIpTunnelConnection* tun = nullptr;
    for (int i = 0; i < KNX_TUNNELING + KNX_TUNNELING_DEVMGMT; i++)
    {
        if (tunnels[i].ChannelId == stateRequest.channelId())
        {
            tun = &tunnels[i];
            break;
        }
    }

    if (tun == nullptr)
    {
#ifdef KNX_LOG_TUNNELING
        print("Channel ID nicht gefunden: ");
        println(stateRequest.channelId());
#endif
        KnxIpStateResponse stateRes(0x00, E_CONNECTION_ID);
        _platform.sendBytesUniCast(src_addr, src_port, stateRes.data(), stateRes.totalLength());
        return;
    }

    if (!endpointMatches(tun, src_addr, src_port, true))
        return;

    // TODO check knx connection!
    // if no connection return E_KNX_CONNECTION

    // TODO check when to send E_DATA_CONNECTION

    tun->lastHeartbeat = millis();
    KnxIpStateResponse stateRes(tun->ChannelId, E_NO_ERROR);
    _platform.sendBytesUniCast(tun->IpAddress, tun->PortCtrl, stateRes.data(), stateRes.totalLength());
}

void IpTunnelServer::HandleDisconnectRequest(uint8_t* buffer, uint16_t length, uint32_t src_addr, uint16_t src_port)
{
    KnxIpDisconnectRequest discReq(buffer, length);

#ifdef KNX_LOG_TUNNELING
    print(">>> Disconnect Channel ID: ");
    println(discReq.channelId());
#endif

    KnxIpTunnelConnection* tun = nullptr;
    for (int i = 0; i < KNX_TUNNELING + KNX_TUNNELING_DEVMGMT; i++)
    {
        if (tunnels[i].ChannelId == discReq.channelId())
        {
            tun = &tunnels[i];
            break;
        }
    }

    if (tun == nullptr)
    {
#ifdef KNX_LOG_TUNNELING
        print("Channel ID nicht gefunden: ");
        println(discReq.channelId());
#endif
        KnxIpDisconnectResponse discRes(0x00, E_CONNECTION_ID);
        _platform.sendBytesUniCast(src_addr, src_port, discRes.data(), discRes.totalLength());
        return;
    }

    if (!endpointMatches(tun, src_addr, src_port, true))
        return;

    KnxIpDisconnectResponse discRes(tun->ChannelId, E_NO_ERROR);
    _platform.sendBytesUniCast(tun->IpAddress, tun->PortCtrl, discRes.data(), discRes.totalLength());
    tun->Reset();
}

void IpTunnelServer::HandleDescriptionRequest(uint8_t* buffer, uint16_t length, uint32_t src_addr, uint16_t src_port)
{
    KnxIpDescriptionRequest descReq(buffer, length);
    KnxIpDescriptionResponse descRes(_ipParameters, _deviceObject);
    const uint16_t responsePort = descReq.hpaiCtrl().ipPortNumber() ?
                                      descReq.hpaiCtrl().ipPortNumber() : src_port;
    _platform.sendBytesUniCast(src_addr, responsePort, descRes.data(), descRes.totalLength());
}

void IpTunnelServer::HandleDeviceConfigurationRequest(uint8_t* buffer, uint16_t length, uint32_t src_addr, uint16_t src_port)
{
    KnxIpConfigRequest confReq(buffer, length);

    KnxIpTunnelConnection* tun = nullptr;
    for (int i = KNX_TUNNELING; i < KNX_TUNNELING + KNX_TUNNELING_DEVMGMT; i++)
    {
        if (tunnels[i].ChannelId == confReq.connectionHeader().channelId())
        {
            tun = &tunnels[i];
            break;
        }
    }

    if (tun == nullptr)
    {
        print("Channel ID nicht gefunden: ");
        println(confReq.connectionHeader().channelId());
        KnxIpTunnelingAck tunnAck;
        tunnAck.serviceTypeIdentifier(DeviceConfigurationAck);
        tunnAck.connectionHeader().length(LEN_CH);
        tunnAck.connectionHeader().channelId(confReq.connectionHeader().channelId());
        tunnAck.connectionHeader().sequenceCounter(confReq.connectionHeader().sequenceCounter());
        tunnAck.connectionHeader().status(E_CONNECTION_ID);
        _platform.sendBytesUniCast(src_addr, src_port, tunnAck.data(), tunnAck.totalLength());
        return;
    }

    if (!endpointMatches(tun, src_addr, src_port, false))
        return;

    const uint8_t sequence = confReq.connectionHeader().sequenceCounter();
    if (sequence == tun->SequenceCounter_R)
    {
        KnxIpTunnelingAck tunnAck;
        tunnAck.serviceTypeIdentifier(DeviceConfigurationAck);
        tunnAck.connectionHeader().length(LEN_CH);
        tunnAck.connectionHeader().channelId(tun->ChannelId);
        tunnAck.connectionHeader().sequenceCounter(sequence);
        tunnAck.connectionHeader().status(E_NO_ERROR);
        _platform.sendBytesUniCast(tun->IpAddress, tun->PortData, tunnAck.data(), tunnAck.totalLength());
        return;
    }

    if ((uint8_t)(sequence - 1) != tun->SequenceCounter_R)
    {
        KnxIpTunnelingAck tunnAck;
        tunnAck.serviceTypeIdentifier(DeviceConfigurationAck);
        tunnAck.connectionHeader().length(LEN_CH);
        tunnAck.connectionHeader().channelId(tun->ChannelId);
        tunnAck.connectionHeader().sequenceCounter(sequence);
        tunnAck.connectionHeader().status(E_SEQUENCE_NUMBER);
        _platform.sendBytesUniCast(tun->IpAddress, tun->PortData, tunnAck.data(), tunnAck.totalLength());
        return;
    }

    KnxIpTunnelingAck tunnAck;
    tunnAck.serviceTypeIdentifier(DeviceConfigurationAck);
    tunnAck.connectionHeader().length(4);
    tunnAck.connectionHeader().channelId(tun->ChannelId);
    tunnAck.connectionHeader().sequenceCounter(confReq.connectionHeader().sequenceCounter());
    tunnAck.connectionHeader().status(E_NO_ERROR);
    _platform.sendBytesUniCast(tun->IpAddress, tun->PortData, tunnAck.data(), tunnAck.totalLength());

    tun->SequenceCounter_R = sequence;
    tun->lastHeartbeat = millis();
    _cemiServer.frameReceived(confReq.frame(), tun->ChannelId);
}

void IpTunnelServer::HandleTunnelingRequest(uint8_t* buffer, uint16_t length, uint32_t src_addr, uint16_t src_port)
{
    KnxIpTunnelingRequest tunnReq(buffer, length);

    KnxIpTunnelConnection* tun = nullptr;
    for (int i = 0; i < KNX_TUNNELING; i++)
    {
        if (tunnels[i].ChannelId == tunnReq.connectionHeader().channelId())
        {
            tun = &tunnels[i];
            break;
        }
    }

    if (tun == nullptr)
    {
#ifdef KNX_LOG_TUNNELING
        print("Channel ID nicht gefunden: ");
        println(tunnReq.connectionHeader().channelId());
#endif
        KnxIpTunnelingAck tunnAck;
        tunnAck.connectionHeader().length(LEN_CH);
        tunnAck.connectionHeader().channelId(tunnReq.connectionHeader().channelId());
        tunnAck.connectionHeader().sequenceCounter(tunnReq.connectionHeader().sequenceCounter());
        tunnAck.connectionHeader().status(E_CONNECTION_ID);
        _platform.sendBytesUniCast(src_addr, src_port, tunnAck.data(), tunnAck.totalLength());
        return;
    }

    if (!endpointMatches(tun, src_addr, src_port, false))
        return;

    uint8_t sequence = tunnReq.connectionHeader().sequenceCounter();
    if (sequence == tun->SequenceCounter_R)
    {
#ifdef KNX_LOG_TUNNELING
        print("Received SequenceCounter again: ");
        println(tunnReq.connectionHeader().sequenceCounter());
#endif
        // we already got this one
        // so just ack it
        KnxIpTunnelingAck tunnAck;
        tunnAck.connectionHeader().length(4);
        tunnAck.connectionHeader().channelId(tun->ChannelId);
        tunnAck.connectionHeader().sequenceCounter(tunnReq.connectionHeader().sequenceCounter());
        tunnAck.connectionHeader().status(E_NO_ERROR);
        _platform.sendBytesUniCast(tun->IpAddress, tun->PortData, tunnAck.data(), tunnAck.totalLength());
        return;
    }
    else if ((uint8_t)(sequence - 1) != tun->SequenceCounter_R)
    {
#ifdef KNX_LOG_TUNNELING
        print("Wrong SequenceCounter: got ");
        print(tunnReq.connectionHeader().sequenceCounter());
        print(" expected ");
        println((uint8_t)(tun->SequenceCounter_R + 1));
#endif
        KnxIpTunnelingAck tunnAck;
        tunnAck.connectionHeader().length(LEN_CH);
        tunnAck.connectionHeader().channelId(tun->ChannelId);
        tunnAck.connectionHeader().sequenceCounter(sequence);
        tunnAck.connectionHeader().status(E_SEQUENCE_NUMBER);
        _platform.sendBytesUniCast(tun->IpAddress, tun->PortData, tunnAck.data(), tunnAck.totalLength());
        return;
    }

    KnxIpTunnelingAck tunnAck;
    tunnAck.connectionHeader().length(4);
    tunnAck.connectionHeader().channelId(tun->ChannelId);
    tunnAck.connectionHeader().sequenceCounter(tunnReq.connectionHeader().sequenceCounter());
    tunnAck.connectionHeader().status(E_NO_ERROR);
    _platform.sendBytesUniCast(tun->IpAddress, tun->PortData, tunnAck.data(), tunnAck.totalLength());

    tun->SequenceCounter_R = tunnReq.connectionHeader().sequenceCounter();

    // The data endpoint and channel above authenticate this tunnel, not the
    // source address carried by its client-provided cEMI frame.  Always bind
    // the frame to the IA assigned to that tunnel so a client cannot
    // impersonate another KNX participant with a non-zero source address.
    tunnReq.frame().sourceAddress(tun->IndividualAddress);

    _cemiServer.frameReceived(tunnReq.frame(), tun->ChannelId);
}

void IpTunnelServer::HandleTunnelAcknowledgement(uint8_t* buffer, uint16_t length,
                                                 uint32_t src_addr, uint16_t src_port,
                                                 bool configChannel)
{
    KnxIpTunnelingAck ack(buffer, length);
    KnxIpTunnelConnection* tun = nullptr;
    const int first = configChannel ? KNX_TUNNELING : 0;
    const int last = configChannel ? KNX_TUNNELING + KNX_TUNNELING_DEVMGMT : KNX_TUNNELING;
    for (int i = first; i < last; i++)
    {
        if (tunnels[i].ChannelId == ack.connectionHeader().channelId())
        {
            tun = &tunnels[i];
            break;
        }
    }

    // ACKs never create state. Accept them only from the endpoint bound at
    // connect time and only for the most recently transmitted sequence.
    if (!endpointMatches(tun, src_addr, src_port, false) ||
        ack.connectionHeader().sequenceCounter() != (uint8_t)(tun->SequenceCounter_S - 1))
        return;

    tun->lastHeartbeat = millis();
}

#endif
