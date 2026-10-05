#pragma once
#include "config.h"
#include "platform.h"
#include "bits.h"

class KnxIpTunnelConnection
{
  public:
    KnxIpTunnelConnection();
    uint8_t ChannelId = 0;
    uint16_t IndividualAddress = 0;
    uint32_t IpAddress = 0;
    uint16_t PortData = 0;
    uint16_t PortCtrl = 0;
    uint8_t SequenceCounter_S = 0;
    uint8_t SequenceCounter_R = 255;
    unsigned long lastHeartbeat = 0;
    bool IsConfig = false;
#ifdef USE_IPSECURE
    uint16_t SecureSessionId = 0;
#endif

    void Reset();

  private:

};
