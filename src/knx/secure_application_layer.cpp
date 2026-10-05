#include "config.h"
#ifdef USE_DATASECURE

#include "secure_application_layer.h"
#include "transport_layer.h"
#include "cemi_frame.h"
#include "association_table_object.h"
#include "address_table_object.h"
#include "security_interface_object.h"
#include "device_object.h"
#include "apdu.h"
#include "bau.h"
#include "string.h"
#include "bits.h"

// Select what cipher modes to include. We need AES128-CBC and AES128-CTR modes.
#define CBC 1
#define CTR 1
#define ECB 0
#include "aes.hpp"

static constexpr uint8_t kSecureDataPdu = 0;
static constexpr uint8_t kSecureSyncRequest = 2;
static constexpr uint8_t kSecureSyncResponse = 3;
static constexpr uint16_t kSecureOverhead = 13;
static constexpr uint64_t kMaxSecureSequence = 0xffffffffffffULL;
static constexpr uint32_t kSyncTimeout = 6000;

// An invalid frame must never underflow the unsigned cEMI allocation length.
static uint16_t plainFrameLength(const APDU& apdu)
{
    return apdu.length() >= 14 ? apdu.length() - kSecureOverhead : 1;
}

SecureApplicationLayer::SecureApplicationLayer(DeviceObject &deviceObj, SecurityInterfaceObject &secIfObj, BusAccessUnit& bau):
    ApplicationLayer(bau),
    _secIfObj(secIfObj),
    _deviceObj(deviceObj)
{
}

void SecureApplicationLayer::groupAddressTable(AddressTableObject &addrTable)
{
    _addrTab = &addrTable;
}

/* from transport layer */

void SecureApplicationLayer::dataGroupIndication(HopCountType hopType, Priority priority, uint16_t tsap, APDU& apdu)
{
    if (_addrTab == nullptr)
        return;

    println("dataGroupIndication");

    if (apdu.type() == SecureService)
    {
        // Will be filled in by decodeSecureApdu()
        SecurityControl secCtrl;

        // Decrypt secure APDU
        // Somehow ugly that we need to know the size in advance here at this point
        uint16_t plainApduLength = plainFrameLength(apdu);
        CemiFrame plainFrame(plainApduLength);
        // Decrypt secure APDU
        if (decodeSecureApdu(apdu, plainFrame.apdu(), secCtrl))
        {
            // Process decrypted inner APDU
            ApplicationLayer::dataGroupIndication(hopType, priority, tsap, plainFrame.apdu(), secCtrl);
        }
        return;
    }

    ApplicationLayer::dataGroupIndication(hopType, priority, tsap, apdu);
}

void SecureApplicationLayer::dataGroupConfirm(AckType ack, HopCountType hopType, Priority priority,  uint16_t tsap, APDU& apdu, bool status)
{
    println("dataGroupConfirm");

    if (apdu.type() == SecureService)
    {
        // We do not care about confirmations of our sync communication
        if (isSyncService(apdu))
        {
            return;
        }

        // Will be filled in by decodeSecureApdu()
        SecurityControl secCtrl;

        // Decrypt secure APDU
        // Somehow ugly that we need to know the size in advance here at this point
        uint16_t plainApduLength = plainFrameLength(apdu);
        CemiFrame plainFrame(plainApduLength);
        // Decrypt secure APDU
        if (decodeSecureApdu(apdu, plainFrame.apdu(), secCtrl, true))
        {
            // Process decrypted inner APDU
            ApplicationLayer::dataGroupConfirm(ack, hopType, priority, tsap, plainFrame.apdu(), secCtrl, status);
        }
        return;
    }

    ApplicationLayer::dataGroupConfirm(ack, hopType, priority, tsap, apdu, status);
}

void SecureApplicationLayer::dataBroadcastIndication(HopCountType hopType, Priority priority, uint16_t source, APDU& apdu)
{
    println("dataBroadcastIndication");

    if (apdu.type() == SecureService)
    {
        // Will be filled in by decodeSecureApdu()
        SecurityControl secCtrl;

        // Decrypt secure APDU
        // Somehow ugly that we need to know the size in advance here at this point
        uint16_t plainApduLength = plainFrameLength(apdu);
        CemiFrame plainFrame(plainApduLength);
        // Decrypt secure APDU
        if (decodeSecureApdu(apdu, plainFrame.apdu(), secCtrl))
        {
            // Process decrypted inner APDU
            ApplicationLayer::dataBroadcastIndication(hopType, priority, source, plainFrame.apdu(), secCtrl);
        }
        return;
    }

    ApplicationLayer::dataBroadcastIndication(hopType, priority, source, apdu);
}

void SecureApplicationLayer::dataBroadcastConfirm(AckType ack, HopCountType hopType, Priority priority, APDU& apdu, bool status)
{
    println("dataBroadcastConfirm");

    if (apdu.type() == SecureService)
    {
        // We do not care about confirmations of our sync communication
        if (isSyncService(apdu))
        {
            return;
        }

        // Will be filled in by decodeSecureApdu()
        SecurityControl secCtrl;

        // Decrypt secure APDU
        // Somehow ugly that we need to know the size in advance here at this point
        uint16_t plainApduLength = plainFrameLength(apdu);
        CemiFrame plainFrame(plainApduLength);
        // Decrypt secure APDU
        if (decodeSecureApdu(apdu, plainFrame.apdu(), secCtrl, true))
        {
            // Process decrypted inner APDU
            ApplicationLayer::dataBroadcastConfirm(ack, hopType, priority, plainFrame.apdu(), secCtrl, status);
        }
        return;
    }
    ApplicationLayer::dataBroadcastConfirm(ack, hopType, priority, apdu, status);
}

void SecureApplicationLayer::dataSystemBroadcastIndication(HopCountType hopType, Priority priority, uint16_t source, APDU& apdu)
{
    println("dataSystemBroadcastIndication");

    if (apdu.type() == SecureService)
    {
        // Will be filled in by decodeSecureApdu()
        SecurityControl secCtrl;

        // Decrypt secure APDU
        // Somehow ugly that we need to know the size in advance here at this point
        uint16_t plainApduLength = plainFrameLength(apdu);
        CemiFrame plainFrame(plainApduLength);
        // Decrypt secure APDU
        if (decodeSecureApdu(apdu, plainFrame.apdu(), secCtrl))
        {
            // Process decrypted inner APDU
            ApplicationLayer::dataSystemBroadcastIndication(hopType, priority, source, plainFrame.apdu(), secCtrl);
        }
        return;
    }

    ApplicationLayer::dataSystemBroadcastIndication(hopType, priority, source, apdu);
}

void SecureApplicationLayer::dataSystemBroadcastConfirm(HopCountType hopType, Priority priority, APDU& apdu, bool status)
{
    println("dataSystemBroadcastConfirm");

    if (apdu.type() == SecureService)
    {
        // We do not care about confirmations of our sync communication
        if (isSyncService(apdu))
        {
            return;
        }

        // Will be filled in by decodeSecureApdu()
        SecurityControl secCtrl;

        // Decrypt secure APDU
        // Somehow ugly that we need to know the size in advance here at this point
        uint16_t plainApduLength = plainFrameLength(apdu);
        CemiFrame plainFrame(plainApduLength);
        // Decrypt secure APDU
        if (decodeSecureApdu(apdu, plainFrame.apdu(), secCtrl, true))
        {
            // Process decrypted inner APDU
            ApplicationLayer::dataSystemBroadcastConfirm(hopType, priority, plainFrame.apdu(), secCtrl, status);
        }
        return;
    }

    ApplicationLayer::dataSystemBroadcastConfirm(hopType, priority, apdu, status);
}

void SecureApplicationLayer::dataIndividualIndication(HopCountType hopType, Priority priority, uint16_t source, APDU& apdu)
{
    println("dataIndividualIndication");

    if (apdu.type() == SecureService)
    {
        // Will be filled in by decodeSecureApdu()
        SecurityControl secCtrl;

        // Decrypt secure APDU
        // Somehow ugly that we need to know the size in advance here at this point
        uint16_t plainApduLength = plainFrameLength(apdu);
        CemiFrame plainFrame(plainApduLength);
        // Decrypt secure APDU
        if (decodeSecureApdu(apdu, plainFrame.apdu(), secCtrl))
        {
            // Process decrypted inner APDU
            ApplicationLayer::dataIndividualIndication(hopType, priority, source, plainFrame.apdu(), secCtrl);
        }
        return;
    }

    ApplicationLayer::dataIndividualIndication(hopType, priority, source, apdu);
}

void SecureApplicationLayer::dataIndividualConfirm(AckType ack, HopCountType hopType, Priority priority, uint16_t source, APDU& apdu, bool status)
{
    println("dataIndividualConfirm");

    if (apdu.type() == SecureService)
    {
        // We do not care about confirmations of our sync communication
        if (isSyncService(apdu))
        {
            return;
        }

        // Will be filled in by decodeSecureApdu()
        SecurityControl secCtrl;

        // Decrypt secure APDU
        // Somehow ugly that we need to know the size in advance here at this point
        uint16_t plainApduLength = plainFrameLength(apdu);
        CemiFrame plainFrame(plainApduLength);
        // Decrypt secure APDU
        if (decodeSecureApdu(apdu, plainFrame.apdu(), secCtrl, true))
        {
            // Process decrypted inner APDU
            ApplicationLayer::dataIndividualConfirm(ack, hopType, priority, source, plainFrame.apdu(), secCtrl, status);
        }
        return;
    }
    else
    {
        ApplicationLayer::dataIndividualConfirm(ack, hopType, priority, source, apdu, status);
    }
}

void SecureApplicationLayer::dataConnectedIndication(Priority priority, uint16_t tsap, APDU& apdu)
{
    println("dataConnectedIndication");

    if (apdu.type() == SecureService)
    {
        // Will be filled in by decodeSecureApdu()
        SecurityControl secCtrl;

        // Decrypt secure APDU
        // Somehow ugly that we need to know the size in advance here at this point
        uint16_t plainApduLength = plainFrameLength(apdu);
        CemiFrame plainFrame(plainApduLength);
        // Decrypt secure APDU
        if (decodeSecureApdu(apdu, plainFrame.apdu(), secCtrl))
        {
            // Process decrypted inner APDU
            ApplicationLayer::dataConnectedIndication(priority, tsap, plainFrame.apdu(), secCtrl);
        }
        return;
    }

    ApplicationLayer::dataConnectedIndication(priority, tsap, apdu);
}

void SecureApplicationLayer::dataConnectedConfirm(uint16_t tsap)
{
    // Just the confirmation issued by the transport layer in case of T_DATA_CONNECTED
    ApplicationLayer::dataConnectedConfirm(tsap, _connectedSecurity);
}

/* to transport layer */

void SecureApplicationLayer::dataGroupRequest(AckType ack, HopCountType hop, Priority priority, uint16_t tsap,
                                               APDU& apdu, const SecurityControl& control)
{
    if (control.dataSecurity == None)
    {
        ApplicationLayer::dataGroupRequest(ack, hop, priority, tsap, apdu, control);
        return;
    }
    if (_addrTab && apdu.length() >= 1 && apdu.length() <= 241)
    {
        apdu.frame().sourceAddress(_deviceObj.individualAddress());
        apdu.frame().destinationAddress(_addrTab->getGroupAddress(tsap));
        apdu.frame().addressType(GroupAddress);
        apdu.frame().systemBroadcast(Broadcast);
        apdu.data()[-1] &= 3;
        CemiFrame encoded(apdu.length() + kSecureOverhead);
        if (createSecureApdu(apdu, encoded.apdu(), control))
        {
            ApplicationLayer::dataGroupRequest(ack, hop, priority, tsap, encoded.apdu(), control);
            return;
        }
    }
    // A rejected encryption is still a failed request: release the BAU GO queue.
    ApplicationLayer::dataGroupConfirm(ack, hop, priority, tsap, apdu, control, false);
}

void SecureApplicationLayer::dataBroadcastRequest(AckType ack, HopCountType hop, Priority priority,
                                                   APDU& apdu, const SecurityControl& control)
{
    if (control.dataSecurity == None)
    {
        ApplicationLayer::dataBroadcastRequest(ack, hop, priority, apdu, control);
        return;
    }
    if (apdu.length() >= 1 && apdu.length() <= 241)
    {
        apdu.frame().sourceAddress(_deviceObj.individualAddress());
        apdu.frame().destinationAddress(0);
        apdu.frame().addressType(GroupAddress);
        apdu.frame().systemBroadcast(Broadcast);
        apdu.data()[-1] &= 3;
        CemiFrame encoded(apdu.length() + kSecureOverhead);
        if (createSecureApdu(apdu, encoded.apdu(), control))
        {
            ApplicationLayer::dataBroadcastRequest(ack, hop, priority, encoded.apdu(), control);
            return;
        }
    }
    ApplicationLayer::dataBroadcastConfirm(ack, hop, priority, apdu, control, false);
}

void SecureApplicationLayer::dataSystemBroadcastRequest(AckType ack, HopCountType hop, Priority priority,
                                                         APDU& apdu, const SecurityControl& control)
{
    if (control.dataSecurity == None)
    {
        ApplicationLayer::dataSystemBroadcastRequest(ack, hop, priority, apdu, control);
        return;
    }
    if (apdu.length() >= 1 && apdu.length() <= 241)
    {
        apdu.frame().sourceAddress(_deviceObj.individualAddress());
        apdu.frame().destinationAddress(0);
        apdu.frame().addressType(GroupAddress);
        apdu.frame().systemBroadcast(SysBroadcast);
        apdu.data()[-1] &= 3;
        CemiFrame encoded(apdu.length() + kSecureOverhead);
        if (createSecureApdu(apdu, encoded.apdu(), control))
        {
            ApplicationLayer::dataSystemBroadcastRequest(ack, hop, priority, encoded.apdu(), control);
            return;
        }
    }
    ApplicationLayer::dataSystemBroadcastConfirm(hop, priority, apdu, control, false);
}

void SecureApplicationLayer::dataIndividualRequest(AckType ack, HopCountType hop, Priority priority,
                                                    uint16_t destination, APDU& apdu, const SecurityControl& control)
{
    if (_localManagementActive)
    {
        localManagementResponse(apdu, control);
        return;
    }
    if (control.dataSecurity == None)
    {
        ApplicationLayer::dataIndividualRequest(ack, hop, priority, destination, apdu, control);
        return;
    }
    if (apdu.length() >= 1 && apdu.length() <= 241)
    {
        apdu.frame().sourceAddress(_deviceObj.individualAddress());
        apdu.frame().destinationAddress(destination);
        apdu.frame().addressType(IndividualAddress);
        apdu.frame().systemBroadcast(Broadcast);
        apdu.data()[-1] &= 3;
        CemiFrame encoded(apdu.length() + kSecureOverhead);
        if (createSecureApdu(apdu, encoded.apdu(), control))
        {
            ApplicationLayer::dataIndividualRequest(ack, hop, priority, destination, encoded.apdu(), control);
            return;
        }
    }
    ApplicationLayer::dataIndividualConfirm(ack, hop, priority, destination, apdu, control, false);
}

void SecureApplicationLayer::dataConnectedRequest(uint16_t tsap, Priority priority, APDU& apdu,
                                                   const SecurityControl& control)
{
    if (_localManagementActive)
    {
        localManagementResponse(apdu, control);
        return;
    }
    _connectedSecurity = control;
    if (control.dataSecurity == None)
    {
        ApplicationLayer::dataConnectedRequest(tsap, priority, apdu, control);
        return;
    }
    if (apdu.length() >= 1 && apdu.length() <= 241)
    {
        apdu.frame().sourceAddress(_deviceObj.individualAddress());
        apdu.frame().destinationAddress(_transportLayer->getConnectionAddress());
        apdu.frame().addressType(IndividualAddress);
        apdu.frame().systemBroadcast(Broadcast);
        apdu.data()[-1] = (apdu.data()[-1] & 3) | 0x40 | _transportLayer->getTpciSeqNum();
        CemiFrame encoded(apdu.length() + kSecureOverhead);
        if (createSecureApdu(apdu, encoded.apdu(), control))
        {
            ApplicationLayer::dataConnectedRequest(tsap, priority, encoded.apdu(), control);
            return;
        }
    }
    ApplicationLayer::dataConnectedConfirm(tsap, control);
}

void SecureApplicationLayer::encryptAesCbc(uint8_t* buffer, uint16_t bufLen, const uint8_t* iv, const uint8_t* key)
{
    // Use zeroes as IV for first round
    uint8_t zeroIv[16] = {0x00};

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, zeroIv);

    // Now encrypt first block B0.
    AES_CBC_encrypt_buffer(&ctx, (uint8_t*) iv, 16);

    // Encrypt remaining buffer
    AES_CBC_encrypt_buffer(&ctx, buffer, bufLen);
}

void SecureApplicationLayer::xcryptAesCtr(uint8_t* buffer, uint16_t bufLen, const uint8_t* iv, const uint8_t* key)
{
    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, key, iv);

    AES_CTR_xcrypt_buffer(&ctx, buffer, bufLen);
}

uint32_t SecureApplicationLayer::calcAuthOnlyMac(uint8_t* apdu, uint8_t apduLength, const uint8_t* key, uint8_t* iv, uint8_t* ctr0)
{
    // EN 50090-3-4 5.1.1.1.3.4.2: empty encrypted payload, all of the
    // inner APDU is associated data after SCF=0. Use MSB32 of the FINAL
    // CBC block, without CTR masking (also verified against current XKNX).
    // The old draft implementation used the first block and failed to
    // authenticate any tail after the first 14 bytes.
    (void)ctr0;
    uint8_t associated[243] = {};
    memcpy(associated + 1, apdu, apduLength);
    return calcConfAuthMac(associated, apduLength + 1, nullptr, 0, key, iv);
}

uint32_t SecureApplicationLayer::calcConfAuthMac(uint8_t* associatedData, uint16_t associatedDataLength,
                            uint8_t* apdu, uint8_t apduLength,
                            const uint8_t* key, uint8_t* iv)
{
    uint16_t bufLen = 2 + associatedDataLength + apduLength; // 2 bytes for the length field (uint16_t)
    // AES-128 operates on blocks of 16 bytes, add padding
    uint16_t bufLenPadded = (bufLen + 15) / 16 * 16;
    uint8_t buffer[272];
    // Make sure to have zeroes everywhere, because of the padding
    memset(buffer, 0x00, bufLenPadded);

    uint8_t* pBuf = buffer;

    pBuf = pushWord(associatedDataLength, pBuf);
    pBuf = pushByteArray(associatedData, associatedDataLength, pBuf);
    if (apduLength != 0)
        pBuf = pushByteArray(apdu, apduLength, pBuf);

    encryptAesCbc(buffer, bufLenPadded, iv, key);

    uint32_t mac;
    popInt(mac, &buffer[bufLenPadded - 16]); // bufLenPadded has a guaranteed minimum size of 16 bytes

    return mac;
}

void SecureApplicationLayer::block0(uint8_t* buffer, uint8_t* seqNum, uint16_t indSrcAddr, uint16_t dstAddr, bool dstAddrIsGroupAddr, uint8_t extFrameFormat, uint8_t tpci, uint8_t apci, uint8_t payloadLength)
{
    uint8_t* pBuf = buffer;
    pBuf = pushByteArray(seqNum, 6, pBuf);
    pBuf = pushWord(indSrcAddr, pBuf);
    pBuf = pushWord(dstAddr, pBuf);
    pBuf = pushByte(0x00, pBuf); // FT: frametype
    pBuf = pushByte( (dstAddrIsGroupAddr ? 0x80 : 0x00) | (extFrameFormat & 0xf), pBuf); // AT: address type
    pBuf = pushByte(tpci, pBuf); // TPCI
    pBuf = pushByte(apci, pBuf); // APCI // draft spec shows something different!
    pBuf = pushByte(0x00, pBuf); // Reserved: fixed 0x00 (really?)
    pBuf = pushByte(payloadLength, pBuf); // Payload length
}

void SecureApplicationLayer::blockCtr0(uint8_t* buffer, uint8_t* seqNum, uint16_t indSrcAddr, uint16_t dstAddr)
{
    uint8_t* pBuf = buffer;
    pBuf = pushByteArray(seqNum, 6, pBuf);
    pBuf = pushWord(indSrcAddr, pBuf);
    pBuf = pushWord(dstAddr, pBuf);
    pBuf = pushInt(0x00000000, pBuf);
    pBuf = pushByte(0x01, pBuf);
}

uint16_t SecureApplicationLayer::groupAddressIndex(uint16_t groupAddr)
{
    // Just for safety reasons, we should never get here, because the dataGroupIndication will return already return early without doing anything
    if (_addrTab == nullptr)
        return 0;
    return _addrTab->getTsap(groupAddr);
}

const uint8_t* SecureApplicationLayer::securityKey(uint16_t addr, bool isGroupAddress)
{
    if (isGroupAddress)
    {
        uint16_t gaIndex = groupAddressIndex(addr);
        if (gaIndex > 0)
            return _secIfObj.groupKey(gaIndex);
    }
    else
    {
        uint16_t iaIndex = _secIfObj.indAddressIndex(addr);
        if (iaIndex > 0)
            return _secIfObj.p2pKey(iaIndex);
    }

    return nullptr;
}

// Outgoing and replay state live in SecurityInterfaceObject's durable journal.
uint64_t SecureApplicationLayer::nextSequenceNumber(bool toolAccess)
{
    return _secIfObj.nextSequenceNumber(toolAccess);
}

void SecureApplicationLayer::updateSequenceNumber(bool toolAccess, uint64_t sequence)
{
    _secIfObj.ensureOutgoingSequenceAtLeast(toolAccess, sequence);
}

uint64_t SecureApplicationLayer::lastValidSequenceNumber(bool toolAccess, uint16_t source)
{
    return _secIfObj.lastValidSequenceNumber(toolAccess, source);
}

void SecureApplicationLayer::updateLastValidSequence(bool toolAccess, uint16_t source, uint64_t sequence)
{
    _secIfObj.acceptIncomingSequence(toolAccess, source, sequence);
}

bool SecureApplicationLayer::requestSequenceSync(uint16_t destination, const SecurityControl& control,
                                                 const uint8_t* targetSerial, bool systemBroadcast)
{
    if (systemBroadcast && (targetSerial == nullptr || destination != 0))
        return false;
    memset(_syncTargetSerial, 0, sizeof(_syncTargetSerial));
    if (targetSerial != nullptr)
        memcpy(_syncTargetSerial, targetSerial, sizeof(_syncTargetSerial));
    return sendSyncRequest(destination, destination == 0, control, systemBroadcast);
}

bool SecureApplicationLayer::sendSyncRequest(uint16_t destination, bool group, const SecurityControl& control,
                                            bool systemBroadcast)
{
    loop();
    if (_outgoingSync.active || control.dataSecurity != DataSecurity::AuthConf)
        return false;
    uint64_t challenge = getRandomNumber();
    if (challenge == 0)
        return false;
    uint8_t payload[6];
    sixBytesFromUInt64(challenge, payload);
    // Full APDU: TPCI, APCI, SCF, seq6, target serial6, challenge6, MAC4.
    CemiFrame frame(24);
    if (!secure(frame.apdu().data() - 1, kSecureSyncRequest, _deviceObj.individualAddress(),
                destination, group, 0, payload, sizeof(payload), control, systemBroadcast))
        return false;
    _outgoingSync.active = true;
    _outgoingSync.peer = destination;
    _outgoingSync.toolAccess = control.toolAccess;
    _outgoingSync.broadcast = group && destination == 0;
    _outgoingSync.systemBroadcast = systemBroadcast;
    _outgoingSync.challenge = challenge;
    _outgoingSync.started = millis();
    // Register BEFORE sending: an in-process transport can return a response synchronously.
    if (systemBroadcast)
        _transportLayer->dataSystemBroadcastRequest(AckDontCare, NetworkLayerParameter, SystemPriority, frame.apdu());
    else if (group)
        _transportLayer->dataBroadcastRequest(AckDontCare, NetworkLayerParameter, SystemPriority, frame.apdu());
    else
        _transportLayer->dataIndividualRequest(AckDontCare, NetworkLayerParameter, SystemPriority, destination, frame.apdu());
    return true;
}

void SecureApplicationLayer::sendSyncResponse(uint16_t destination, bool group, const SecurityControl& control,
                                              uint64_t remoteNext, bool systemBroadcast)
{
    const uint64_t localNext = nextSequenceNumber(control.toolAccess);
    if (localNext == 0 || localNext > kMaxSecureSequence || remoteNext == 0 || remoteNext > kMaxSecureSequence)
        return;
    uint8_t payload[12];
    sixBytesFromUInt64(localNext, payload);
    sixBytesFromUInt64(remoteNext, payload + 6);
    CemiFrame frame(24);
    if (!secure(frame.apdu().data() - 1, kSecureSyncResponse, _deviceObj.individualAddress(),
                destination, group, 0, payload, sizeof(payload), control, systemBroadcast))
        return;
    _lastSyncRes = millis();
    _syncResponseSent = true;
    if (systemBroadcast)
        _transportLayer->dataSystemBroadcastRequest(AckDontCare, NetworkLayerParameter, SystemPriority, frame.apdu());
    else if (group)
        _transportLayer->dataBroadcastRequest(AckDontCare, NetworkLayerParameter, SystemPriority, frame.apdu());
    else
        _transportLayer->dataIndividualRequest(AckDontCare, NetworkLayerParameter, SystemPriority, destination, frame.apdu());
}

void SecureApplicationLayer::receivedSyncRequest(uint16_t source, uint16_t destination, bool group,
                                                 const SecurityControl& control, uint8_t* sequence,
                                                 uint64_t challenge, bool systemBroadcast)
{
    const uint64_t remoteNext = sixBytesToUInt64(sequence);
    const uint64_t last = lastValidSequenceNumber(control.toolAccess, source);
    if (remoteNext == 0 || last >= kMaxSecureSequence)
        return;
    uint64_t next = last + 1;
    if (remoteNext > next)
    {
        if (!_secIfObj.acceptIncomingSequence(control.toolAccess, source, remoteNext - 1))
            return;
        next = remoteNext;
    }
    _incomingSync.active = true;
    _incomingSync.peer = source;
    _incomingSync.toolAccess = control.toolAccess;
    _incomingSync.broadcast = group && destination == 0;
    _incomingSync.systemBroadcast = systemBroadcast;
    _incomingSync.challenge = challenge;
    _incomingSync.started = millis();
    sendSyncResponse(_incomingSync.broadcast ? 0 : source, _incomingSync.broadcast, control, next, systemBroadcast);
    _incomingSync.active = false;
}

void SecureApplicationLayer::receivedSyncResponse(uint16_t remote, const SecurityControl& control, uint8_t* payload)
{
    if (!_outgoingSync.active || _outgoingSync.toolAccess != control.toolAccess ||
        (!_outgoingSync.broadcast && _outgoingSync.peer != remote))
        return;
    const uint64_t remoteNext = sixBytesToUInt64(payload);
    const uint64_t localNext = sixBytesToUInt64(payload + 6);
    if (remoteNext == 0 || localNext == 0)
        return;
    const uint64_t last = lastValidSequenceNumber(control.toolAccess, remote);
    if (remoteNext - 1 > last && !_secIfObj.acceptIncomingSequence(control.toolAccess, remote, remoteNext - 1))
        return;
    if (!_secIfObj.ensureOutgoingSequenceAtLeast(control.toolAccess, localNext))
        return;
    _outgoingSync.active = false;
}

bool SecureApplicationLayer::decrypt(uint8_t* output, uint16_t capacity, uint16_t source, uint16_t destination,
                                      bool group, uint8_t tpci, uint8_t* asdu, uint16_t asduLength,
                                      SecurityControl& control, bool systemBroadcast, bool localConfirmation,
                                      const uint8_t* explicitKey)
{
    if (asduLength < 13 || capacity > 242)
        return false;
    const uint8_t scf = asdu[0];
    const bool tool = (scf & 0x80) != 0;
    const bool sbc = (scf & 8) != 0;
    const uint8_t sai = (scf >> 4) & 7;
    const uint8_t service = scf & 7;
    const bool syncRequest = service == kSecureSyncRequest;
    const bool syncResponse = service == kSecureSyncResponse;
    const bool authenticationOnly = sai == 0;
    const uint64_t wireSequence = sixBytesToUInt64(asdu + 1);
    auto fail = [&](uint8_t code) {
        _secIfObj.recordFailure(code, source, destination, scf, wireSequence);
        return false;
    };
    if (sai > 1 || (service != kSecureDataPdu && !syncRequest && !syncResponse) || sbc != systemBroadcast ||
        (tool && (authenticationOnly || (group && destination != 0))) || (sbc && !tool) ||
        ((syncRequest || syncResponse) && authenticationOnly) || (tpci & 0x80) != 0 ||
        (group && (tpci & 0xfc) != 0))
        return fail(1);
    if ((syncRequest || syncResponse) && asduLength != 23)
        return fail(1);
    if (service == kSecureDataPdu && asduLength < 13)
        return fail(1);
    if (localConfirmation && (source != _deviceObj.individualAddress() || service != kSecureDataPdu))
        return false;
    if (!localConfirmation && (source == 0 || source == _deviceObj.individualAddress()))
        return fail(4);
    if (!tool && !localConfirmation && !_secIfObj.isKnownSender(source))
        return fail(4);
    // Confirmations use the outgoing peer key, indications the sending peer key.
    const uint8_t* key = explicitKey ? explicitKey :
        (group && destination != 0 ? securityKey(destination, true) :
         (tool ? _secIfObj.toolKey() : securityKey(localConfirmation ? destination : source, false)));
    if (key == nullptr)
        return fail(4);
    uint8_t sequence[6];
    memcpy(sequence, asdu + 1, sizeof(sequence));
    const uint8_t* serial = syncRequest ? asdu + 7 : nullptr;
    const uint8_t* ciphertext = asdu + (syncRequest ? 13 : 7);
    const uint16_t payloadLength = asduLength - (syncRequest ? 17 : 11);
    if (payloadLength > 242 || (service == kSecureDataPdu && payloadLength > capacity))
        return fail(1);
    if (service == kSecureDataPdu &&
        (wireSequence == 0 || (!localConfirmation && wireSequence <= lastValidSequenceNumber(tool, source))))
        return fail(2);
    if (syncRequest)
    {
        const uint8_t zeroSerial[6] = {};
        if (wireSequence == 0 ||
            (memcmp(serial, _deviceObj.propertyData(PID_SERIAL_NUMBER), 6) != 0 &&
             (systemBroadcast || group || destination != _deviceObj.individualAddress() ||
              memcmp(serial, zeroSerial, 6) != 0)))
            return fail(4);
        if (_syncResponseSent && static_cast<uint32_t>(millis() - _lastSyncRes) < 1000)
            return false;
    }
    if (syncResponse)
    {
        loop();
        if (!_outgoingSync.active || _outgoingSync.toolAccess != tool ||
            _outgoingSync.systemBroadcast != sbc ||
            (!_outgoingSync.broadcast && _outgoingSync.peer != source))
            return fail(4);
        uint8_t challenge[6];
        sixBytesFromUInt64(_outgoingSync.challenge, challenge);
        for (size_t i = 0; i < 6; ++i)
            sequence[i] ^= challenge[i];
    }
    uint8_t iv[16] = {};
    block0(iv, sequence, source, destination, group, 0, tpci, SecureService & 0xff,
           authenticationOnly ? 0 : payloadLength);
    uint8_t counter[16] = {};
    blockCtr0(counter, sequence, source, destination);
    uint32_t receivedMac;
    popInt(receivedMac, ciphertext + payloadLength);
    uint8_t plaintext[256] = {};
    if (authenticationOnly)
    {
        memcpy(plaintext, ciphertext, payloadLength);
        const uint32_t expected = calcAuthOnlyMac(plaintext, payloadLength, key, iv, counter);
        if ((expected ^ receivedMac) != 0)
            return fail(3);
    }
    else
    {
        uint8_t encrypted[256] = {};
        pushInt(receivedMac, encrypted);
        memcpy(encrypted + 4, ciphertext, payloadLength);
        xcryptAesCtr(encrypted, payloadLength + 4, counter, key);
        uint32_t decryptedMac;
        popInt(decryptedMac, encrypted);
        memcpy(plaintext, encrypted + 4, payloadLength);
        uint8_t associated[7] = {scf};
        if (syncRequest)
            memcpy(associated + 1, serial, 6);
        const uint32_t expected = calcConfAuthMac(associated, syncRequest ? 7 : 1,
                                                plaintext, payloadLength, key, iv);
        if ((expected ^ decryptedMac) != 0)
            return fail(3);
    }
    SecurityControl authenticated;
    authenticated.toolAccess = tool;
    authenticated.dataSecurity = authenticationOnly ? DataSecurity::Auth : DataSecurity::AuthConf;
    if (syncRequest)
    {
        receivedSyncRequest(source, destination, group, authenticated, sequence,
                            sixBytesToUInt64(plaintext), sbc);
        return false; // internal service, never an application indication
    }
    if (syncResponse)
    {
        receivedSyncResponse(source, authenticated, plaintext);
        return false;
    }
    // The inner APDU is unnumbered and cannot recursively wrap a secure service.
    if (payloadLength < 2 || (plaintext[0] & 0xfc) != 0 ||
        (((plaintext[0] & 3) << 8) | plaintext[1]) == SecureService)
        return fail(1);
    if (!localConfirmation && !_secIfObj.acceptIncomingSequence(tool, source, wireSequence))
        return fail(2); // never deliver until durable anti-replay state has committed
    memcpy(output, plaintext, payloadLength);
    control = authenticated;
    return true;
}

bool SecureApplicationLayer::decodeSecureApdu(APDU& secureApdu, APDU& plainApdu, SecurityControl& control,
                                               bool localConfirmation, const uint8_t* explicitKey)
{
    if (secureApdu.type() != SecureService || secureApdu.length() < 14)
        return false;
    const bool systemBroadcast = secureApdu.frame().systemBroadcast() == SysBroadcast;
    if (!decrypt(plainApdu.data() - 1, plainApdu.length() + 1,
                 secureApdu.frame().sourceAddress(), secureApdu.frame().destinationAddress(),
                 secureApdu.frame().addressType() == GroupAddress, secureApdu.data()[-1],
                 secureApdu.data() + 1, secureApdu.length() - 1, control,
                 systemBroadcast, localConfirmation, explicitKey))
        return false;
    plainApdu.frame().sourceAddress(secureApdu.frame().sourceAddress());
    plainApdu.frame().destinationAddress(secureApdu.frame().destinationAddress());
    plainApdu.frame().addressType(secureApdu.frame().addressType());
    plainApdu.frame().systemBroadcast(secureApdu.frame().systemBroadcast());
    return true;
}

bool SecureApplicationLayer::secure(uint8_t* output, uint16_t service, uint16_t source, uint16_t destination,
                                     bool group, uint8_t tpci, uint8_t* payload, uint16_t payloadLength,
                                     const SecurityControl& control, bool systemBroadcast, const uint8_t* explicitKey)
{
    const bool tool = control.toolAccess;
    const bool conf = control.dataSecurity == DataSecurity::AuthConf;
    const bool syncRequest = service == kSecureSyncRequest;
    const bool syncResponse = service == kSecureSyncResponse;
    if (payloadLength > 242 || control.dataSecurity == DataSecurity::None ||
        (service != kSecureDataPdu && !syncRequest && !syncResponse) ||
        (tool && (!conf || (group && destination != 0))) || (systemBroadcast && !tool) ||
        ((syncRequest || syncResponse) && !conf) ||
        (syncRequest && payloadLength != 6) || (syncResponse && payloadLength != 12))
        return false;
    const uint8_t* key = explicitKey ? explicitKey : (tool ? _secIfObj.toolKey() : securityKey(destination, group));
    if (key == nullptr)
        return false;
    uint64_t number;
    if (syncResponse)
    {
        if (!_incomingSync.active || _incomingSync.toolAccess != tool)
            return false;
        number = getRandomNumber();
        if (number == 0)
            return false;
    }
    else if (!_secIfObj.reserveOutgoingSequence(tool, number))
        return false;
    if (number == 0 || number > kMaxSecureSequence)
        return false;
    uint8_t sequence[6];
    sixBytesFromUInt64(number, sequence);
    uint8_t wireSequence[6];
    memcpy(wireSequence, sequence, 6);
    if (syncResponse)
    {
        uint8_t challenge[6];
        sixBytesFromUInt64(_incomingSync.challenge, challenge);
        for (size_t i = 0; i < 6; ++i)
            wireSequence[i] ^= challenge[i];
    }
    tpci = (tpci & 0x7c) | (SecureService >> 8);
    const uint8_t scf = service | (tool ? 0x80 : 0) | (conf ? 0x10 : 0) | (systemBroadcast ? 8 : 0);
    output[0] = tpci;
    output[1] = SecureService & 0xff;
    output[2] = scf;
    memcpy(output + 3, wireSequence, 6);
    uint8_t associated[7] = {scf};
    uint8_t* encoded = output + 9;
    if (syncRequest)
    {
        memcpy(encoded, _syncTargetSerial, 6);
        memcpy(associated + 1, _syncTargetSerial, 6);
        encoded += 6;
    }
    uint8_t iv[16] = {};
    block0(iv, sequence, source, destination, group, 0, tpci, SecureService & 0xff, conf ? payloadLength : 0);
    uint8_t counter[16] = {};
    blockCtr0(counter, sequence, source, destination);
    if (conf)
    {
        uint8_t encrypted[256] = {};
        pushInt(calcConfAuthMac(associated, syncRequest ? 7 : 1, payload, payloadLength, key, iv), encrypted);
        memcpy(encrypted + 4, payload, payloadLength);
        xcryptAesCtr(encrypted, payloadLength + 4, counter, key);
        memcpy(encoded, encrypted + 4, payloadLength);
        memcpy(encoded + payloadLength, encrypted, 4);
    }
    else
    {
        memcpy(encoded, payload, payloadLength);
        pushInt(calcAuthOnlyMac(payload, payloadLength, key, iv, counter), encoded + payloadLength);
    }
    return true;
}

bool SecureApplicationLayer::createSecureApdu(APDU& plain, APDU& encoded, const SecurityControl& control)
{
    if (plain.length() < 1 || plain.length() > 241 || encoded.length() != plain.length() + 13)
        return false;
    uint8_t inner[242];
    memcpy(inner, plain.data() - 1, plain.length() + 1);
    inner[0] &= 3;
    const uint8_t tpci = plain.data()[-1] & 0x7c;
    return secure(encoded.data() - 1, kSecureDataPdu, plain.frame().sourceAddress(),
                  plain.frame().destinationAddress(), plain.frame().addressType() == GroupAddress,
                  tpci, inner, plain.length() + 1, control, plain.frame().systemBroadcast() == SysBroadcast);
}

bool SecureApplicationLayer::localManagementIndication(APDU& request, bool connected,
                                                       void (*respond)(void*, APDU&), void* context)
{
    if (_localManagementActive || respond == nullptr || request.length() < 1 ||
        (request.data()[-1] & 0xfc) != 0 || request.type() == SecureService)
        return false;
    // The public TL wire format is known, but the normative SAL local nonce
    // mapping is not yet verified. SA=DA=0 with independent per-direction
    // counters risks reusing the same CTR nonce under the Tool Key. Do not
    // offer guessed Secure local management or advertise DeviceMgmt v2.
    // A local transport APDU must never become a bus telegram or borrow the
    // active bus connection. The callback scope is strictly synchronous.
    request.frame().sourceAddress(0);
    request.frame().destinationAddress(0);
    request.frame().addressType(IndividualAddress);
    request.frame().systemBroadcast(Broadcast);
    _localManagementActive = true;
    _localManagementRespond = respond;
    _localManagementContext = context;
    SecurityControl control{};
    // Plain local management retains anonymous privilege even on an
    // authenticated KNXnet/IP administrator session.
    if (connected)
        ApplicationLayer::dataConnectedIndication(SystemPriority, 0, request, control);
    else
        ApplicationLayer::dataIndividualIndication(NetworkLayerParameter, SystemPriority, 0, request, control);
    _localManagementContext = nullptr;
    _localManagementRespond = nullptr;
    _localManagementActive = false;
    return true;
}

void SecureApplicationLayer::localManagementResponse(APDU& response, const SecurityControl& control)
{
    if (!_localManagementActive || _localManagementRespond == nullptr || response.length() < 1)
        return;
    if (control.dataSecurity == DataSecurity::None)
    {
        response.data()[-1] &= 3;
        _localManagementRespond(_localManagementContext, response);
        return;
    }
    // Secure local transport remains unavailable until its nonce/key-rotation
    // behavior is verified against the normative specification and ETS.
}

bool SecureApplicationLayer::decodeProxyGroupFrame(APDU& encoded, APDU& plain, const uint8_t* key)
{
    if (key == nullptr || encoded.length() < 14 || encoded.frame().addressType() != GroupAddress ||
        encoded.frame().destinationAddress() == 0 || encoded.data()[1] != 0x10)
        return false;
    SecurityControl control;
    return decodeSecureApdu(encoded, plain, control, false, key) &&
           control.dataSecurity == DataSecurity::AuthConf && !control.toolAccess;
}

bool SecureApplicationLayer::encodeProxyGroupFrame(APDU& plain, APDU& encoded, const uint8_t* key,
                                                   uint16_t source, uint16_t destination)
{
    if (key == nullptr || source != _deviceObj.individualAddress() || destination == 0 ||
        plain.length() < 1 || plain.length() > 241 || encoded.length() != plain.length() + 13)
        return false;
    SecurityControl control;
    control.toolAccess = false;
    control.dataSecurity = DataSecurity::AuthConf;
    uint8_t inner[242];
    memcpy(inner, plain.data() - 1, plain.length() + 1);
    inner[0] &= 3;
    if (!secure(encoded.data() - 1, kSecureDataPdu, source, destination, true, 0,
                inner, plain.length() + 1, control, false, key))
        return false;
    encoded.frame().sourceAddress(source);
    encoded.frame().destinationAddress(destination);
    encoded.frame().addressType(GroupAddress);
    encoded.frame().systemBroadcast(Broadcast);
    return true;
}

uint64_t SecureApplicationLayer::getRandomNumber()
{
    uint8_t bytes[6];
    return _secIfObj.randomBytes(bytes, sizeof(bytes)) ? sixBytesToUInt64(bytes) : 0;
}

void SecureApplicationLayer::loop()
{
    if (_outgoingSync.active && static_cast<uint32_t>(millis() - _outgoingSync.started) >= kSyncTimeout)
        _outgoingSync.active = false;
    if (_incomingSync.active && static_cast<uint32_t>(millis() - _incomingSync.started) >= kSyncTimeout)
        _incomingSync.active = false;
}

bool SecureApplicationLayer::isSyncService(APDU& apdu)
{
    if (apdu.length() < 2)
        return false;
    const uint8_t service = apdu.data()[1] & 7;
    return service == kSecureSyncRequest || service == kSecureSyncResponse;
}
#endif
