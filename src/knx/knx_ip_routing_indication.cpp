#include "knx_ip_routing_indication.h"
#include <cstring>

#ifdef USE_IP
namespace
{
uint8_t* copyRoutingCemiFrame(uint8_t* destination, CemiFrame& frame)
{
    memcpy(destination, frame.data(), frame.totalLenght());
    return destination;
}
}

CemiFrame& KnxIpRoutingIndication::frame()
{
    return _frame;
}


KnxIpRoutingIndication::KnxIpRoutingIndication(uint8_t* data, 
    uint16_t length) : KnxIpFrame(data, length), _frame(data + headerLength(), length - headerLength())
{
}

KnxIpRoutingIndication::KnxIpRoutingIndication(CemiFrame frame)
    : KnxIpFrame(frame.totalLenght() + LEN_KNXIP_HEADER),
      _frame(copyRoutingCemiFrame(_data + LEN_KNXIP_HEADER, frame), frame.totalLenght())
{
    serviceTypeIdentifier(RoutingIndication);
}
#endif
