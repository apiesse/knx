#pragma once

#include "config.h"
#ifdef USE_DATASECURE

#include "interface_object.h"
#include "knx_types.h"
#include "platform.h"

#ifndef KNX_SECURE_P2P_KEYS
#define KNX_SECURE_P2P_KEYS 32
#endif
#ifndef KNX_SECURE_GROUP_KEYS
#define KNX_SECURE_GROUP_KEYS 256
#endif
#ifndef KNX_SECURE_SENDERS
#define KNX_SECURE_SENDERS 128
#endif
#ifndef KNX_SECURE_TOOL_SENDERS
#define KNX_SECURE_TOOL_SENDERS 16
#endif
#ifndef KNX_SECURE_GROUP_OBJECTS
#define KNX_SECURE_GROUP_OBJECTS 256
#endif
#ifndef KNX_SECURE_SEQUENCE_RESERVATION
#define KNX_SECURE_SEQUENCE_RESERVATION 256
#endif
#ifndef KNX_SECURE_FAILURE_LOG_SIZE
#define KNX_SECURE_FAILURE_LOG_SIZE 16
#endif

class SecurityInterfaceObject: public InterfaceObject
{
public:
  SecurityInterfaceObject();
  ~SecurityInterfaceObject() override;

  void bindPlatform(Platform& platform);
  bool isFactoryProvisioned() const;
  bool randomBytes(uint8_t* data, size_t length);
  uint64_t nextSequenceNumber(bool toolAccess) const;
  bool reserveOutgoingSequence(bool toolAccess, uint64_t& sequence);
  bool ensureOutgoingSequenceAtLeast(bool toolAccess, uint64_t sequence);
  uint64_t lastValidSequenceNumber(bool toolAccess, uint16_t sender);
  bool acceptIncomingSequence(bool toolAccess, uint16_t sender, uint64_t sequence);
  bool isKnownSender(uint16_t sender);
  void recordFailure(uint8_t code, uint16_t source, uint16_t destination,
                     uint8_t control, uint64_t sequence);

  void masterReset(EraseCode eraseCode, uint8_t channel) override;

  bool isSecurityModeEnabled();

  bool isLoaded();

  const uint8_t* toolKey();                           // returns single tool key (ETS)
  const uint8_t* p2pKey(uint16_t addressIndex);       // returns p2p key for IA index
  const uint8_t* groupKey(uint16_t addressIndex);     // returns group key for group address index

  uint16_t indAddressIndex(uint16_t indAddr);         // returns 1-based index of address in security IA table

  void setSequenceNumber(bool toolAccess, uint64_t seqNum);
  uint64_t getLastValidSequenceNumber(uint16_t deviceAddr);
  void setLastValidSequenceNumber(uint16_t deviceAddr, uint64_t seqNum);

  DataSecurity getGroupObjectSecurity(uint16_t index);

  LoadState loadState();
  uint8_t* save(uint8_t* buffer) override;
  const uint8_t* restore(const uint8_t* buffer) override;
  uint16_t saveSize() override;

private:
  void setSecurityMode(bool enabled);

  void clearFailureLog();
  void getFailureCounters(uint8_t* data);
  uint8_t getFromFailureLogByIndex(uint8_t index, uint8_t* data, uint8_t maxDataLen);

  void errorCode(ErrorCode errorCode);

  void loadEvent(const uint8_t* data);
  void loadEventUnloaded(const uint8_t* data);
  void loadEventLoading(const uint8_t* data);
  void loadEventLoaded(const uint8_t* data);
  void loadEventError(const uint8_t* data);

  void loadState(LoadState newState);
  LoadState _state = LS_UNLOADED;

  bool _securityModeEnabled {false};

  uint16_t getNumberOfElements(PropertyID propId);

  void loadOutgoingSequences();
  uint64_t sequenceProperty(bool toolAccess) const;
  void writeSequenceProperty(bool toolAccess, uint64_t sequence);
  bool persistSequence(uint32_t recordId, uint64_t value);
  bool readSequence(uint32_t recordId, uint64_t& value);
  uint64_t configuredReplayFloor(uint16_t sender);

  struct ReplayState
  {
    uint16_t sender = 0;
    uint64_t sequence = 0;
    bool toolAccess = false;
    bool occupied = false;
  };
  ReplayState* replayState(bool toolAccess, uint16_t sender);
  ReplayState _replay[KNX_SECURE_SENDERS + KNX_SECURE_TOOL_SENDERS];
  Platform* _platform = nullptr;
  uint64_t _nextSequence[2] = {1, 1};
  uint64_t _reservedSequence[2] = {0, 0};
  bool _journalHealthy = false;
  bool _factoryProvisioned = false;
  uint16_t _failureCounters[4] = {};
  uint8_t _failureLog[KNX_SECURE_FAILURE_LOG_SIZE][12] = {};
  uint8_t _failureLogCount = 0;
  uint8_t _failureLogNext = 0;

  // Our FDSK
  uint8_t _fdsk[16] = {};
  uint8_t _secReport[3] = {};
  uint8_t _secReportCtrl[3] = {};
};
#endif
