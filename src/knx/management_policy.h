#pragma once

#include <stdint.h>

namespace KnxManagementPolicy
{
    /* In the product profile, the physical and time-limited programming-mode
       window is the only available authorization boundary. KNX levels count
       from 0 (most privileged) to 3 (least privileged). */
    constexpr uint8_t accessLevel(bool programmingMode)
    {
        return programmingMode ? 0 : 3;
    }

    constexpr bool memoryAccessAllowed(bool programmingMode)
    {
        return programmingMode;
    }

    constexpr bool readAllowed(uint8_t propertyAccess, bool programmingMode)
    {
        const uint8_t requiredLevel = (propertyAccess >> 4) & 0x0F;
        return accessLevel(programmingMode) <= requiredLevel;
    }

    constexpr bool writeAllowed(uint8_t propertyAccess, bool programmingMode)
    {
        const uint8_t requiredLevel = propertyAccess & 0x0F;
        return programmingMode && accessLevel(programmingMode) <= requiredLevel;
    }
}
