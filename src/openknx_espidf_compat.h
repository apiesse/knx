#ifndef OPENKNX_ESP_IDF_COMPAT_H
#define OPENKNX_ESP_IDF_COMPAT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DEC
#define DEC 10
#endif

#ifndef HEX
#define HEX 16
#endif

#ifndef INPUT
#define INPUT 0x0
#endif

#ifndef OUTPUT
#define OUTPUT 0x1
#endif

#ifndef INPUT_PULLUP
#define INPUT_PULLUP 0x2
#endif

#ifndef INPUT_PULLDOWN
#define INPUT_PULLDOWN 0x3
#endif

#ifndef OUTPUT_OPEN_DRAIN
#define OUTPUT_OPEN_DRAIN 0x4
#endif

#ifndef LOW
#define LOW 0x0
#endif

#ifndef HIGH
#define HIGH 0x1
#endif

#ifndef CHANGE
#define CHANGE 2
#endif

#ifndef FALLING
#define FALLING 3
#endif

#ifndef RISING
#define RISING 4
#endif

#ifndef lowByte
#define lowByte(val) ((val) & 255)
#endif

#ifndef highByte
#define highByte(val) (((val) >> ((sizeof(val) - 1U) << 3U)) & 255)
#endif

#ifndef bitRead
#define bitRead(val, bitno) (((val) >> (bitno)) & 1U)
#endif

typedef void (*voidFuncPtr)(void);

void delay(uint32_t ms);
void delayMicroseconds(unsigned int us);
uint32_t millis(void);
uint32_t micros(void);
void pinMode(uint32_t pin, uint32_t mode);
void digitalWrite(uint32_t pin, uint32_t value);
uint32_t digitalRead(uint32_t pin);
void attachInterrupt(uint32_t pin, voidFuncPtr callback, uint32_t mode);

#ifdef __cplusplus
}

void print(const char value[]);
void print(char value);
void print(unsigned char value, int base);
void print(int value, int base);
void print(unsigned int value, int base);
void print(long value, int base);
void print(unsigned long value, int base);
void print(long long value, int base);
void print(unsigned long long value, int base);
void print(double value);

void println(const char value[]);
void println(char value);
void println(unsigned char value, int base);
void println(int value, int base);
void println(unsigned int value, int base);
void println(long value, int base);
void println(unsigned long value, int base);
void println(long long value, int base);
void println(unsigned long long value, int base);
void println(double value);
void println(void);
#endif

#endif /* OPENKNX_ESP_IDF_COMPAT_H */
