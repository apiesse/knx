#ifndef ESPIDF_PLATFORM_H
#define ESPIDF_PLATFORM_H

#include "driver/uart.h"
#include "knx/platform.h"
#include "nvs.h"

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
    void restart() override;
    void fatalError() override;

    void setupMultiCast(uint32_t addr, uint16_t port) override;
    void closeMultiCast() override;
    bool sendBytesMultiCast(uint8_t *buffer, uint16_t len) override;
    int readBytesMultiCast(uint8_t *buffer, uint16_t maxLen, uint32_t &src_addr, uint16_t &src_port) override;
    bool sendBytesUniCast(uint32_t addr, uint16_t port, uint8_t *buffer, uint16_t len) override;

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

    nvs_handle_t _nvs_handle = 0;
    uint8_t *_eeprom_buffer = nullptr;
    uint32_t _eeprom_size = 0;
    static constexpr const char *_nvs_namespace = "eeprom";
    static constexpr const char *_nvs_key = "eeprom";
};

#endif /* ESPIDF_PLATFORM_H */
