#ifndef ESPIDF_PLATFORM_H
#define ESPIDF_PLATFORM_H

#include "driver/uart.h"
#include "knx/platform.h"
#include "nvs.h"
#include "mbedtls/version.h"
#if MBEDTLS_VERSION_NUMBER >= 0x04000000
// ESP-IDF 6 exports TF-PSA builtin headers for the low-level APIs.  The
// independently seeded DRBG is essential when TP runs with RF entropy disabled.
#include "mbedtls/private/ctr_drbg.h"
#else
#include "mbedtls/ctr_drbg.h"
#endif

typedef struct esp_netif_obj esp_netif_t;
struct sockaddr_in;

class EspIdfPlatform : public Platform
{
  public:
    EspIdfPlatform(uart_port_t uart_num = UART_NUM_2, int rx_pin = -1, int tx_pin = -1);
    ~EspIdfPlatform();

    void knxUartConfig(uart_port_t uart_num, int8_t rxPin, int8_t txPin, uint32_t baud_rate);
    void setNetif(esp_netif_t *netif);

    uint32_t currentIpAddress() override;
    uint32_t currentSubnetMask() override;
    uint32_t currentDefaultGateway() override;
    void macAddress(uint8_t *addr) override;
    uint32_t uniqueSerialNumber() override;
    // Call once during early boot, before RF, ADC or I2S drivers are started.
    bool initializeSecureRandom();
    bool fillRandom(uint8_t* data, size_t length) override;
    bool secureX25519(const uint8_t privateKey[32], const uint8_t peerPublic[32], uint8_t shared[32]) override;
    bool secureSha256(const uint8_t* data, size_t length, uint8_t output[32]) override;
    bool readFactoryDeviceKey(uint8_t key[16]) override;
    int readSecurityState(uint32_t recordId, uint8_t* data, size_t capacity) override;
    bool writeSecurityState(uint32_t recordId, const uint8_t* data, size_t length) override;
    void restart() override;
    void fatalError() override;

    void setupMultiCast(uint32_t addr, uint16_t port) override;
    void closeMultiCast() override;
    bool sendBytesMultiCast(uint8_t *buffer, uint16_t len) override;
    int readBytesMultiCast(uint8_t *buffer, uint16_t maxLen, uint32_t &src_addr, uint16_t &src_port) override;
    bool sendBytesUniCast(uint32_t addr, uint16_t port, uint8_t *buffer, uint16_t len) override;
    bool setupSecureTcp(uint16_t port) override;
    int acceptSecureTcp(uint32_t& peerAddress, uint16_t& peerPort) override;
    int readSecureTcp(int connection, uint8_t* buffer, uint16_t capacity) override;
    bool sendSecureTcp(int connection, uint8_t* buffer, uint16_t length) override;
    void closeSecureTcp(int connection) override;
    void closeSecureTcpListener() override;

    uint8_t *getEepromBuffer(uint32_t size) override;
    void commitToEeprom() override;

  private:
    uart_port_t _uart_num;
    int8_t _rxPin;
    int8_t _txPin;

    esp_netif_t *_netif = nullptr;
    int _sock = -1;
    struct sockaddr_in *_remote_addr = nullptr;
    uint32_t _multicast_addr = 0;
    uint16_t _multicast_port = 0;
    int _secure_listener = -1;
    int _secure_connections[16];
    mbedtls_ctr_drbg_context _secure_random;
    bool _secure_random_ready = false;
    bool _secure_entropy_enabled = false;
    static int secureEntropy(void* context, unsigned char* data, size_t length);
    static int secureRandom(void* context, unsigned char* data, size_t length);
    bool isSecureConnection(int connection) const;

    nvs_handle_t _nvs_handle = 0;
    uint8_t *_eeprom_buffer = nullptr;
    uint32_t _eeprom_size = 0;
    static constexpr const char *_nvs_namespace = "eeprom";
    static constexpr const char *_nvs_key = "eeprom";
};

#endif /* ESPIDF_PLATFORM_H */
