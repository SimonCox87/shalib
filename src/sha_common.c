#include <../include/sha_common.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// Functions that build message schedule
inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ ((~x) & z);
}

inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

// Padding functions - for final block
void sha1_256_pad(uint32_t buff_len, uint64_t total_len, uint8_t *buffer, int byte_set)
{
    int i;
    uint32_t len = buff_len;

    if (len >= 56) {
        buffer[len] = 0x80;
    } else {
        memset(buffer + len, 0, 64 - len);
        if (!byte_set) buffer[len] = 0x80;
        uint64_t bit_len = total_len * 8;
        buffer[56] = (bit_len >> 56) & 0xFF;    
        buffer[57] = (bit_len >> 48) & 0xFF;
        buffer[58] = (bit_len >> 40) & 0xFF;
        buffer[59] = (bit_len >> 32) & 0xFF;
        buffer[60] = (bit_len >> 24) & 0xFF;
        buffer[61] = (bit_len >> 16) & 0xFF;
        buffer[62] = (bit_len >> 8)  & 0xFF;
        buffer[63] =  bit_len        & 0xFF;
    }
}