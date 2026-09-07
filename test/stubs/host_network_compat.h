#pragma once

#include <cstdint>

// The embedded builds obtain htonl from lwIP. The Windows object-only compile
// has no socket SDK in its freestanding compiler sysroot, so provide the same
// byte-order operation solely for this host syntax check.
#ifndef htonl
#define htonl(value) __builtin_bswap32((uint32_t)(value))
#endif
