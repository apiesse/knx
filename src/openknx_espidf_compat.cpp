#include "openknx_espidf_compat.h"

#include "driver/gpio.h"
#include "esp_err.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <cstdio>
#include <type_traits>

static gpio_int_type_t compat_gpio_intr_type(uint32_t mode)
{
    switch (mode)
    {
    case RISING:
        return GPIO_INTR_POSEDGE;
    case FALLING:
        return GPIO_INTR_NEGEDGE;
    case CHANGE:
    default:
        return GPIO_INTR_ANYEDGE;
    }
}

extern "C" void delay(uint32_t ms)
{
    vTaskDelay(pdMS_TO_TICKS(ms));
}

extern "C" void delayMicroseconds(unsigned int us)
{
    esp_rom_delay_us(us);
}

extern "C" uint32_t millis(void)
{
    return (uint32_t) (esp_timer_get_time() / 1000ULL);
}

extern "C" uint32_t micros(void)
{
    return (uint32_t) esp_timer_get_time();
}

extern "C" void pinMode(uint32_t pin, uint32_t mode)
{
    gpio_config_t io_conf = {};
    io_conf.pin_bit_mask = (1ULL << pin);
    io_conf.mode = GPIO_MODE_INPUT;
    io_conf.pull_up_en = GPIO_PULLUP_DISABLE;
    io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;

    switch (mode)
    {
    case OUTPUT:
        io_conf.mode = GPIO_MODE_OUTPUT;
        break;
    case INPUT_PULLUP:
        io_conf.pull_up_en = GPIO_PULLUP_ENABLE;
        break;
    case INPUT_PULLDOWN:
        io_conf.pull_down_en = GPIO_PULLDOWN_ENABLE;
        break;
    case OUTPUT_OPEN_DRAIN:
        io_conf.mode = GPIO_MODE_OUTPUT_OD;
        break;
    default:
        break;
    }

    gpio_config(&io_conf);
}

extern "C" void digitalWrite(uint32_t pin, uint32_t value)
{
    gpio_set_level((gpio_num_t) pin, (uint32_t) (value != 0U));
}

extern "C" uint32_t digitalRead(uint32_t pin)
{
    return (uint32_t) gpio_get_level((gpio_num_t) pin);
}

extern "C" void attachInterrupt(uint32_t pin, voidFuncPtr callback, uint32_t mode)
{
    gpio_config_t io_conf = {};
    io_conf.pin_bit_mask = (1ULL << pin);
    io_conf.mode = GPIO_MODE_INPUT;
    io_conf.pull_up_en = GPIO_PULLUP_ENABLE;
    io_conf.intr_type = compat_gpio_intr_type(mode);

    gpio_config(&io_conf);

    esp_err_t err = gpio_install_isr_service(0);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE)
    {
        return;
    }

    gpio_isr_handler_add((gpio_num_t) pin, (gpio_isr_t) callback, NULL);
}

template <typename T>
static void compat_print_integer(T value, int base)
{
    if (base == HEX)
    {
        std::printf("%llX", (unsigned long long) value);
        return;
    }

    if constexpr (std::is_signed<T>::value)
    {
        std::printf("%lld", (long long) value);
    }
    else
    {
        std::printf("%llu", (unsigned long long) value);
    }
}

void print(const char value[])
{
    std::printf("%s", value);
}

void print(char value)
{
    std::printf("%c", value);
}

void print(unsigned char value, int base)
{
    compat_print_integer(value, base);
}

void print(int value, int base)
{
    compat_print_integer(value, base);
}

void print(unsigned int value, int base)
{
    compat_print_integer(value, base);
}

void print(long value, int base)
{
    compat_print_integer(value, base);
}

void print(unsigned long value, int base)
{
    compat_print_integer(value, base);
}

void print(long long value, int base)
{
    compat_print_integer(value, base);
}

void print(unsigned long long value, int base)
{
    compat_print_integer(value, base);
}

void print(double value)
{
    std::printf("%g", value);
}

void println(const char value[])
{
    std::printf("%s\n", value);
}

void println(char value)
{
    std::printf("%c\n", value);
}

void println(unsigned char value, int base)
{
    print(value, base);
    println();
}

void println(int value, int base)
{
    print(value, base);
    println();
}

void println(unsigned int value, int base)
{
    print(value, base);
    println();
}

void println(long value, int base)
{
    print(value, base);
    println();
}

void println(unsigned long value, int base)
{
    print(value, base);
    println();
}

void println(long long value, int base)
{
    print(value, base);
    println();
}

void println(unsigned long long value, int base)
{
    print(value, base);
    println();
}

void println(double value)
{
    print(value);
    println();
}

void println(void)
{
    std::printf("\n");
}
