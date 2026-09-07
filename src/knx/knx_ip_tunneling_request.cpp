#include "knx_ip_tunneling_request.h"
#include <cstring>

#ifdef USE_IP
namespace
{
uint8_t* copyCemiFrame(uint8_t* destination, CemiFrame& frame)
{
    memcpy(destination, frame.data(), frame.totalLenght());
    return destination;
}
}

KnxIpTunnelingRequest::KnxIpTunnelingRequest(uint8_t* data, 
    uint16_t length) : KnxIpFrame(data, length), _frame(data + LEN_CH + headerLength(), length - LEN_CH - headerLength()), _ch(_data + headerLength())
{
}

KnxIpTunnelingRequest::KnxIpTunnelingRequest(CemiFrame frame)
    : KnxIpFrame(frame.totalLenght() + LEN_CH + LEN_KNXIP_HEADER),
      // Populate the owned KNXnet/IP buffer before CemiFrame derives any of
      // its NPDU/TPDU/APDU views from the embedded cEMI bytes.
      _frame(copyCemiFrame(_data + LEN_CH + LEN_KNXIP_HEADER, frame), frame.totalLenght()),
      _ch(_data + LEN_KNXIP_HEADER)
{
    serviceTypeIdentifier(TunnelingRequest);
}

CemiFrame& KnxIpTunnelingRequest::frame()
{
    return _frame;
}

KnxIpCH& KnxIpTunnelingRequest::connectionHeader()
{
    return _ch;
}
#endif
