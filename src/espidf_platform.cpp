#include "espidf_platform.h"

#include "TPUart/Interface/EspIdf.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include "nvs_flash.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

static const char *KTAG = "KNX_PLAT";

EspIdfPlatform::EspIdfPlatform(uart_port_t uart_num, int rx_pin, int tx_pin)
    : _uart_num(uart_num), _rxPin(rx_pin), _txPin(tx_pin), _remote_addr(new sockaddr_in{})
{
    _memoryType = Eeprom;

    if (_rxPin >= 0 && _txPin >= 0)
    {
        interface(new TPUart::Interface::EspIdf(uart_num, rx_pin, tx_pin, 19200));
    }
}

EspIdfPlatform::~EspIdfPlatform()
{
    if (_sock != -1)
    {
        closeMultiCast();
    }
    if (_eeprom_buffer != nullptr)
    {
        free(_eeprom_buffer);
        _eeprom_buffer = nullptr;
    }
    if (_nvs_handle != 0)
    {
        nvs_close(_nvs_handle);
    }
    delete _remote_addr;
    _remote_addr = nullptr;
}

void EspIdfPlatform::knxUartConfig(uart_port_t uart_num, int8_t rxPin, int8_t txPin, uint32_t baud_rate)
{
    if (interface() != nullptr)
    {
        delete interface();
        interface(nullptr);
    }

    _uart_num = uart_num;
    _rxPin = rxPin;
    _txPin = txPin;
    if (rxPin >= 0 && txPin >= 0)
    {
        interface(new TPUart::Interface::EspIdf(uart_num, rxPin, txPin, baud_rate));
    }
}

void EspIdfPlatform::setNetif(esp_netif_t *netif)
{
    _netif = netif;
}

void EspIdfPlatform::fatalError()
{
    ESP_LOGE(KTAG, "FATAL ERROR. System halted.");
    while (true)
    {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

uint32_t EspIdfPlatform::currentIpAddress()
{
    if (_netif == nullptr)
    {
        return 0;
    }

    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(_netif, &ip_info);
    return ip_info.ip.addr;
}

uint32_t EspIdfPlatform::currentSubnetMask()
{
    if (_netif == nullptr)
    {
        return 0;
    }

    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(_netif, &ip_info);
    return ip_info.netmask.addr;
}

uint32_t EspIdfPlatform::currentDefaultGateway()
{
    if (_netif == nullptr)
    {
        return 0;
    }

    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(_netif, &ip_info);
    return ip_info.gw.addr;
}

void EspIdfPlatform::macAddress(uint8_t *addr)
{
    if (_netif != nullptr)
    {
        esp_netif_get_mac(_netif, addr);
    }
    else
    {
        esp_efuse_mac_get_default(addr);
    }
}

uint32_t EspIdfPlatform::uniqueSerialNumber()
{
    uint8_t mac[6];
    esp_efuse_mac_get_default(mac);
    uint64_t chipid = 0;

    for (int i = 0; i < 6; i++)
    {
        chipid |= ((uint64_t) mac[i] << (i * 8));
    }

    return (uint32_t) ((chipid >> 32) ^ (chipid & 0xFFFFFFFF));
}

void EspIdfPlatform::restart()
{
    ESP_LOGI(KTAG, "Restarting system...");
    esp_restart();
}

void EspIdfPlatform::setupMultiCast(uint32_t addr, uint16_t port)
{
    // Platform addresses use host-order integers (as do HPAI/getInt and the
    // Arduino backends); BSD socket fields require network byte order.
    _multicast_addr = htonl(addr);
    _multicast_port = port;

    _sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (_sock < 0)
    {
        ESP_LOGE(KTAG, "Failed to create socket: errno %d", errno);
        return;
    }

    sockaddr_in saddr = {};
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(_sock, (sockaddr *) &saddr, sizeof(saddr)) < 0)
    {
        ESP_LOGE(KTAG, "Failed to bind socket: errno %d", errno);
        close(_sock);
        _sock = -1;
        return;
    }

    ip_mreq imreq = {};
    imreq.imr_interface.s_addr = IPADDR_ANY;
    imreq.imr_multiaddr.s_addr = _multicast_addr;
    if (setsockopt(_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imreq, sizeof(imreq)) < 0)
    {
        ESP_LOGE(KTAG, "Failed to join multicast group: errno %d", errno);
        close(_sock);
        _sock = -1;
        return;
    }

    ESP_LOGI(KTAG, "Multicast joined on port %d", port);
}

void EspIdfPlatform::closeMultiCast()
{
    if (_sock != -1)
    {
        close(_sock);
        _sock = -1;
    }
}

bool EspIdfPlatform::sendBytesMultiCast(uint8_t *buffer, uint16_t len)
{
    if (_sock < 0)
    {
        return false;
    }

    sockaddr_in dest_addr = {};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(_multicast_port);
    dest_addr.sin_addr.s_addr = _multicast_addr;

    int sent = sendto(_sock, buffer, len, 0, (sockaddr *) &dest_addr, sizeof(dest_addr));
    if (sent < 0)
    {
        ESP_LOGE(KTAG, "sendBytesMultiCast failed: errno %d", errno);
        return false;
    }

    return sent == len;
}

int EspIdfPlatform::readBytesMultiCast(uint8_t *buffer, uint16_t maxLen, uint32_t &src_addr, uint16_t &src_port)
{
    if (_sock < 0 || _remote_addr == nullptr)
    {
        return 0;
    }

    socklen_t socklen = sizeof(*_remote_addr);
    int len = recvfrom(_sock, buffer, maxLen, 0, (sockaddr *) _remote_addr, &socklen);
    if (len <= 0)
    {
        return 0;
    }

    src_addr = ntohl(_remote_addr->sin_addr.s_addr);
    src_port = ntohs(_remote_addr->sin_port);
    return len;
}

bool EspIdfPlatform::sendBytesUniCast(uint32_t addr, uint16_t port, uint8_t *buffer, uint16_t len)
{
    if (_sock < 0 || _remote_addr == nullptr)
    {
        return false;
    }

    sockaddr_in dest_addr = {};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = (addr == 0) ? _remote_addr->sin_addr.s_addr : htonl(addr);
    dest_addr.sin_port = (port == 0) ? _remote_addr->sin_port : htons(port);

    if (sendto(_sock, buffer, len, 0, (sockaddr *) &dest_addr, sizeof(dest_addr)) < 0)
    {
        ESP_LOGE(KTAG, "sendBytesUniCast failed: errno %d", errno);
        return false;
    }

    return true;
}

uint8_t *EspIdfPlatform::getEepromBuffer(uint32_t size)
{
    if (_eeprom_buffer != nullptr && _eeprom_size == size)
    {
        return _eeprom_buffer;
    }

    if (_eeprom_buffer != nullptr)
    {
        free(_eeprom_buffer);
        _eeprom_buffer = nullptr;
    }
    if (_nvs_handle != 0)
    {
        nvs_close(_nvs_handle);
        _nvs_handle = 0;
    }

    _eeprom_size = size;
    _eeprom_buffer = static_cast<uint8_t *>(malloc(size));
    if (_eeprom_buffer == nullptr)
    {
        ESP_LOGE(KTAG, "Failed to allocate EEPROM buffer (%" PRIu32 " bytes)", size);
        fatalError();
        return nullptr;
    }

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err != ESP_OK)
    {
        ESP_LOGE(KTAG, "NVS init failed: %s", esp_err_to_name(err));
        fatalError();
        return nullptr;
    }

    err = nvs_open(_nvs_namespace, NVS_READWRITE, &_nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(KTAG, "NVS open failed: %s", esp_err_to_name(err));
        free(_eeprom_buffer);
        _eeprom_buffer = nullptr;
        fatalError();
        return nullptr;
    }

    size_t required_size = size;
    err = nvs_get_blob(_nvs_handle, _nvs_key, _eeprom_buffer, &required_size);
    if (err != ESP_OK || required_size != size)
    {
        ESP_LOGI(KTAG, "Initializing fresh EEPROM buffer (%" PRIu32 " bytes)", size);
        memset(_eeprom_buffer, 0xFF, size);
    }
    else
    {
        ESP_LOGI(KTAG, "Loaded %u bytes from NVS", (unsigned) required_size);
    }

    return _eeprom_buffer;
}

void EspIdfPlatform::commitToEeprom()
{
    if (_eeprom_buffer == nullptr || _nvs_handle == 0)
    {
        return;
    }

    esp_err_t err = nvs_set_blob(_nvs_handle, _nvs_key, _eeprom_buffer, _eeprom_size);
    if (err == ESP_OK)
    {
        err = nvs_commit(_nvs_handle);
    }

    if (err == ESP_OK)
    {
        ESP_LOGI(KTAG, "EEPROM committed (%" PRIu32 " bytes)", _eeprom_size);
    }
    else
    {
        ESP_LOGE(KTAG, "EEPROM commit failed: %s", esp_err_to_name(err));
    }
}
