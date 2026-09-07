#pragma once

// RouterObject and RfMediumObject reach Platform only through Memory. Platform
// stores this type as a pointer, so a declaration is sufficient for compiling
// those implementation units without pulling a target-specific UART backend.
namespace TPUart
{
namespace Interface
{
class Abstract;
}
}
