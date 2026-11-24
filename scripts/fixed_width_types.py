"""Fixed-width integer aliases shared by Clang's probe and VC9's wrapper.

VC9 predates <cstdint>; use C++03-compatible typedefs, not 'using' aliases.
Both compiler inputs must resolve the model's std::uint32_t spelling equally.
The target is 32-bit x86; intptr_t and uintptr_t are 32-bit here.
"""

CPP_FIXED_WIDTH_TYPES = """typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef int intptr_t;
typedef unsigned int uintptr_t;
namespace std {
    typedef ::int8_t int8_t;
    typedef ::uint8_t uint8_t;
    typedef ::int16_t int16_t;
    typedef ::uint16_t uint16_t;
    typedef ::int32_t int32_t;
    typedef ::uint32_t uint32_t;
    typedef ::int64_t int64_t;
    typedef ::uint64_t uint64_t;
    typedef ::intptr_t intptr_t;
    typedef ::uintptr_t uintptr_t;
}
"""
