#if defined(ESP_PLATFORM) && !defined(ARDUINO)
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
#include "esp_random.h"
#include "bootloader_random.h"
#include "mbedtls/version.h"
#if MBEDTLS_VERSION_NUMBER >= 0x04000000
#include "mbedtls/private/ecp.h"
#include "mbedtls/private/sha256.h"
#else
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#endif
#ifndef MBEDTLS_PRIVATE
#define MBEDTLS_PRIVATE(member) member
#endif

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

static const char *KTAG = "KNX_PLAT";

EspIdfPlatform::EspIdfPlatform(uart_port_t uart_num, int rx_pin, int tx_pin)
    : _uart_num(uart_num), _rxPin(rx_pin), _txPin(tx_pin), _remote_addr(new sockaddr_in{})
{
    _memoryType = Eeprom;
    mbedtls_ctr_drbg_init(&_secure_random);
    for (int& connection : _secure_connections)
        connection = -1;

    if (_rxPin >= 0 && _txPin >= 0)
    {
        interface(new TPUart::Interface::EspIdf(uart_num, rx_pin, tx_pin, 19200));
    }
}

EspIdfPlatform::~EspIdfPlatform()
{
    closeSecureTcpListener();
    for (int connection : _secure_connections)
        if (connection >= 0)
            closeSecureTcp(connection);
    mbedtls_ctr_drbg_free(&_secure_random);
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

int EspIdfPlatform::secureEntropy(void* context, unsigned char* data, size_t length)
{
    if (!static_cast<EspIdfPlatform*>(context)->_secure_entropy_enabled)
        return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    esp_fill_random(data, length);
    return 0;
}

int EspIdfPlatform::secureRandom(void* context, unsigned char* data, size_t length)
{
    return static_cast<EspIdfPlatform*>(context)->fillRandom(data, length) ? 0 : MBEDTLS_ERR_ECP_RANDOM_FAILED;
}

bool EspIdfPlatform::initializeSecureRandom()
{
    if (_secure_random_ready)
        return true;
    // A live hardware entropy source is required; bootloader-seeded esp_random
    // alone is insufficient on a TP product that has neither Wi-Fi nor BT active.
    // This must run before ADC/RF/I2S users, never while those drivers are active.
    static const unsigned char personalization[] = "OpenKNX Secure";
    bootloader_random_enable();
    _secure_entropy_enabled = true;
    const int result = mbedtls_ctr_drbg_seed(&_secure_random, secureEntropy, this,
        personalization, sizeof(personalization) - 1);
    bootloader_random_disable();
    _secure_entropy_enabled = false;
    _secure_random_ready = result == 0;
    // Subsequent reseeds must not quietly draw from an inactive hardware source.
    // Product entropy refresh can instead explicitly seed again during safe boot.
    mbedtls_ctr_drbg_set_reseed_interval(&_secure_random, INT32_MAX);
    return _secure_random_ready;
}

bool EspIdfPlatform::fillRandom(uint8_t* data, size_t length)
{
    if (!data || !length || !_secure_random_ready)
        return false;
    while (length)
    {
        const size_t count = length < MBEDTLS_CTR_DRBG_MAX_REQUEST ? length : MBEDTLS_CTR_DRBG_MAX_REQUEST;
        if (mbedtls_ctr_drbg_random(&_secure_random, data, count) != 0)
            return false;
        data += count;
        length -= count;
    }
    return true;
}

bool EspIdfPlatform::secureSha256(const uint8_t* data, size_t length, uint8_t output[32])
{
    if (!output || (!data && length))
        return false;
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    return mbedtls_sha256(data, length, output, 0) == 0;
#else
    return mbedtls_sha256_ret(data, length, output, 0) == 0;
#endif
}

bool EspIdfPlatform::secureX25519(const uint8_t privateKey[32], const uint8_t peerPublic[32], uint8_t shared[32])
{
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
    if (!privateKey || !peerPublic || !shared || !_secure_random_ready)
        return false;
    uint8_t scalar[32], publicPoint[32];
    memcpy(scalar, privateKey, sizeof(scalar));
    memcpy(publicPoint, peerPublic, sizeof(publicPoint));
    scalar[0] &= 248;
    scalar[31] = (scalar[31] & 127) | 64;
    publicPoint[31] &= 127;
    mbedtls_ecp_group group;
    mbedtls_ecp_point peer, result;
    mbedtls_mpi secret;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&peer);
    mbedtls_ecp_point_init(&result);
    mbedtls_mpi_init(&secret);
    int status = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_CURVE25519);
    if (!status) status = mbedtls_mpi_read_binary_le(&secret, scalar, 32);
    if (!status) status = mbedtls_mpi_read_binary_le(&peer.MBEDTLS_PRIVATE(X), publicPoint, 32);
    if (!status) status = mbedtls_mpi_lset(&peer.MBEDTLS_PRIVATE(Z), 1);
    if (!status) status = mbedtls_ecp_mul(&group, &result, &secret, &peer, secureRandom, this);
    if (!status) status = mbedtls_mpi_write_binary_le(&result.MBEDTLS_PRIVATE(X), shared, 32);
    mbedtls_mpi_free(&secret);
    mbedtls_ecp_point_free(&result);
    mbedtls_ecp_point_free(&peer);
    mbedtls_ecp_group_free(&group);
    volatile uint8_t* erase = scalar;
    for (unsigned index = 0; index < sizeof(scalar); ++index)
        erase[index] = 0;
    uint8_t anySet = 0;
    if (!status)
        for (unsigned index = 0; index < 32; ++index)
            anySet |= shared[index];
    if (status || !anySet)
        memset(shared, 0, 32);
    return status == 0 && anySet;
#else
    (void)privateKey; (void)peerPublic; (void)shared;
    return false;
#endif
}

bool EspIdfPlatform::readFactoryDeviceKey(uint8_t key[16])
{
    if (!key || nvs_flash_init() != ESP_OK)
        return false;
    nvs_handle_t handle = 0;
    if (nvs_open("knx_provision", NVS_READONLY, &handle) != ESP_OK)
        return false;
    size_t length = 16;
    const esp_err_t result = nvs_get_blob(handle, "fdsk", key, &length);
    nvs_close(handle);
    if (result != ESP_OK || length != 16)
    {
        memset(key, 0, 16);
        return false;
    }
    return true;
}

int EspIdfPlatform::readSecurityState(uint32_t recordId, uint8_t* data, size_t capacity)
{
    if (!data || !capacity || nvs_flash_init() != ESP_OK)
        return -1;
    nvs_handle_t handle = 0;
    esp_err_t result = nvs_open("knx_secure", NVS_READONLY, &handle);
    if (result == ESP_ERR_NVS_NOT_FOUND)
        return 0;
    if (result != ESP_OK)
        return -1;
    char key[10];
    snprintf(key, sizeof(key), "s%08" PRIx32, recordId);
    size_t length = capacity;
    result = nvs_get_blob(handle, key, data, &length);
    nvs_close(handle);
    if (result == ESP_ERR_NVS_NOT_FOUND)
        return 0;
    return result == ESP_OK && length <= capacity ? static_cast<int>(length) : -1;
}

bool EspIdfPlatform::writeSecurityState(uint32_t recordId, const uint8_t* data, size_t length)
{
    if (!data || !length || nvs_flash_init() != ESP_OK)
        return false;
    nvs_handle_t handle = 0;
    if (nvs_open("knx_secure", NVS_READWRITE, &handle) != ESP_OK)
        return false;
    char key[10];
    snprintf(key, sizeof(key), "s%08" PRIx32, recordId);
    esp_err_t result = nvs_set_blob(handle, key, data, length);
    if (result == ESP_OK)
        result = nvs_commit(handle);
    nvs_close(handle);
    return result == ESP_OK;
}

bool EspIdfPlatform::setupSecureTcp(uint16_t port)
{
    closeSecureTcpListener();
    const int listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener < 0)
        return false;
    const int reuse = 1;
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0 ||
        bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0 ||
        listen(listener, 4) < 0 || fcntl(listener, F_SETFL, O_NONBLOCK) < 0)
    {
        close(listener);
        return false;
    }
    _secure_listener = listener;
    return true;
}

int EspIdfPlatform::acceptSecureTcp(uint32_t& peerAddress, uint16_t& peerPort)
{
    if (_secure_listener < 0)
        return -1;
    sockaddr_in peer = {};
    socklen_t length = sizeof(peer);
    const int connection = accept(_secure_listener, reinterpret_cast<sockaddr*>(&peer), &length);
    if (connection < 0)
        return -1;
    for (int& slot : _secure_connections)
        if (slot < 0 && fcntl(connection, F_SETFL, O_NONBLOCK) == 0)
        {
            slot = connection;
            peerAddress = ntohl(peer.sin_addr.s_addr);
            peerPort = ntohs(peer.sin_port);
            return connection;
        }
    close(connection);
    return -1;
}

bool EspIdfPlatform::isSecureConnection(int connection) const
{
    if (connection < 0)
        return false;
    for (int slot : _secure_connections)
        if (slot == connection)
            return true;
    return false;
}

int EspIdfPlatform::readSecureTcp(int connection, uint8_t* buffer, uint16_t capacity)
{
    if (!buffer || !capacity || !isSecureConnection(connection))
        return -1;
    const int count = recv(connection, buffer, capacity, MSG_DONTWAIT);
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return 0;
    return count > 0 ? count : -1;
}

bool EspIdfPlatform::sendSecureTcp(int connection, uint8_t* buffer, uint16_t length)
{
    if (!buffer || !length || !isSecureConnection(connection))
        return false;
    // A partial stream write cannot be retried as a new secure packet.  The
    // caller closes the session on failure; no truncated frame is reused.
    return send(connection, buffer, length, MSG_DONTWAIT) == length;
}

void EspIdfPlatform::closeSecureTcp(int connection)
{
    if (!isSecureConnection(connection))
        return;
    shutdown(connection, SHUT_RDWR);
    close(connection);
    for (int& slot : _secure_connections)
        if (slot == connection)
            slot = -1;
}

void EspIdfPlatform::closeSecureTcpListener()
{
    if (_secure_listener >= 0)
        close(_secure_listener);
    _secure_listener = -1;
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
#if !defined(USE_DATASECURE) && !defined(USE_IPSECURE)
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
#endif
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
    if (err == ESP_ERR_NVS_INVALID_LENGTH || (err == ESP_OK && required_size != size))
    {
        // NVS updates blobs atomically, so a stored blob that is larger than
        // the current KNX EEPROM layout can prevent the first replacement from
        // fitting. This key is owned exclusively by the KNX platform; discard
        // only that incompatible image and let commissioning create a new one.
        ESP_LOGW(KTAG, "Discarding incompatible KNX EEPROM blob (%u bytes, expected %" PRIu32 ")",
                 (unsigned) required_size, size);
        err = nvs_erase_key(_nvs_handle, _nvs_key);
        if (err == ESP_OK)
        {
            err = nvs_commit(_nvs_handle);
        }
        if (err != ESP_OK)
        {
            ESP_LOGE(KTAG, "Failed to erase incompatible KNX EEPROM blob: %s", esp_err_to_name(err));
        }
    }

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

#endif // native ESP-IDF only
