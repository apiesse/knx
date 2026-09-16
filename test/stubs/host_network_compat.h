#pragma once

#include <cstdint>

// The embedded builds obtain htonl from lwIP. The Windows object-only compile
// has no socket SDK in its freestanding compiler sysroot, so provide the same
// byte-order operation solely for this host syntax check.
#if defined(__linux__)
#include <arpa/inet.h>
#elif !defined(htonl)
#define htonl(value) __builtin_bswap32((uint32_t)(value))
#endif
