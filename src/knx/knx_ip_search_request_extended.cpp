#include "knx_ip_search_request_extended.h"
#include "bits.h"
#include "service_families.h"
#if KNX_SERVICE_FAMILY_CORE >= 2
#ifdef USE_IP
KnxIpSearchRequestExtended::KnxIpSearchRequestExtended(uint8_t* data, uint16_t length)
    : KnxIpFrame(data, length), _hpai(data + LEN_KNXIP_HEADER)
{
    if (data == nullptr || length < LEN_KNXIP_HEADER + LEN_IPHPAI)
    {
        _valid = false;
        return;
    }
    if(length == LEN_KNXIP_HEADER + LEN_IPHPAI) return; //we dont have SRPs

    uint16_t currentPos = LEN_KNXIP_HEADER + LEN_IPHPAI;
    while(currentPos < length)
    {
        // Every SRP starts with length/type. Reject zero/one-byte and
        // truncated structures before reading the type or advancing; a zero
        // length previously kept this loop spinning forever.
        const uint8_t srpLength = data[currentPos];
        if (srpLength < 2 || srpLength > length - currentPos)
        {
            _valid = false;
            return;
        }

        const uint8_t rawType = data[currentPos + 1];
        switch(rawType & 0x7F)
        {
            case 0x01:
                if (srpLength != 2) { _valid = false; return; }
                srpByProgMode = true;
                break;

            case 0x02:
                if (srpLength != 8) { _valid = false; return; }
                srpByMacAddr = true;
                srpMacAddr = data + currentPos + 2;
                break;

            case 0x03:
                if ((srpLength - 2) % 2 != 0) { _valid = false; return; }
                srpByService = true;
                srpServiceFamilies = data + currentPos;
                break;

            case 0x04:
                srpRequestDIBs = true;
                for(uint8_t i = 0; i < srpLength - 2; i++)
                {
                    if(data[currentPos+i+2] == 0) continue;
                    if(data[currentPos+i+2] >= REQUESTED_DIBS_MAX)
                    {
                        print("Requested DIBs too high ");
                        continue;
                    }
                    requestedDIBs[data[currentPos+i+2]] = true;
                }
                break;

            default:
                // Unknown mandatory SRPs make the request unsatisfiable;
                // optional unknown SRPs are skipped using their checked size.
                if ((rawType & 0x80) != 0)
                {
                    _valid = false;
                    return;
                }
                break;
        }
        currentPos += srpLength;
    };
}

IpHostProtocolAddressInformation& KnxIpSearchRequestExtended::hpai()
{
    return _hpai;
}

bool KnxIpSearchRequestExtended::requestedDIB(uint8_t code)
{
    if(code >= REQUESTED_DIBS_MAX) return false;
    return requestedDIBs[code];
}
#endif
#endif
