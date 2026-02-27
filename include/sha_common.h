#include <stdint.h>
#ifndef SHA_COMMON_H
#define SHA_COMMON_H

// Common rotation algorithms that build message schedule
inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z);
inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z);

// Common padding for SHA-1 and SHA-256
void sha1_256_pad(uint32_t buff_len, uint64_t total_len, uint8_t *buffer, int byte_set);

#endif