#include "../include/sha.h"
#include "../include/sha_common.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// H constants
static const uint32_t H[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// K constants
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// hash state struct 
typedef struct {
    uint32_t h[8]; // current hash state (H0 .. H7)
    uint64_t total_len; // total message length in bytes
    uint8_t buffer[64]; // stores partial block
    uint32_t buffer_len; // number of bytes currently in buffer
} SHA256_CTX ;

// Initialise hash state variable
static SHA256_CTX ctx;

// Preprocessing Functions
static void create_block(const uint8_t *message, uint32_t *block);
static void process(uint8_t *data);
// Bit manipulation functions
static inline uint32_t Rotr(uint32_t w, int n);
static inline uint32_t big_sigma0(uint32_t x);
static inline uint32_t big_sigma1(uint32_t x);
static inline uint32_t small_sigma0(uint32_t x);
static inline uint32_t small_sigma1(uint32_t x);

// Initialise context state struct
void sha256_init(void)
{
    ctx.h[0] = H[0];
    ctx.h[1] = H[1]; 
    ctx.h[2] = H[2]; 
    ctx.h[3] = H[3]; 
    ctx.h[4] = H[4]; 
    ctx.h[5] = H[5]; 
    ctx.h[6] = H[6]; 
    ctx.h[7] = H[7];
    ctx.buffer_len = 0;
    ctx.total_len = 0;
    memset(ctx.buffer, 0, 64);
}

// Process the blocks
void sha256_update(const uint8_t *data, size_t len)
{  
    ctx.total_len += len;

    if (ctx.buffer_len > 0) {
        size_t space = 64 - ctx.buffer_len;
        size_t to_copy = len < space ? len : space;

        memcpy(ctx.buffer + ctx.buffer_len, data, to_copy);

        ctx.buffer_len += to_copy;
        data += to_copy;
        len -= to_copy;

        if (ctx.buffer_len == 64) {
            process(ctx.buffer);
            ctx.buffer_len = 0;
        }
    }

    while(len >= 64) {
        process((uint8_t *) data);
        data += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(ctx.buffer, data, len);
        ctx.buffer_len = len;
    }
}

// Build and process final block(s)
void sha256_final(uint32_t *hash)
{
    int i, b_set = 0;

    sha1_256_pad(ctx.buffer_len, ctx.total_len, ctx.buffer, b_set);
    process(ctx.buffer);

    if (ctx.buffer_len >= 56) {
        b_set = 1;
        ctx.buffer_len = 0;
        sha1_256_pad(ctx.buffer_len, ctx.total_len, ctx.buffer, b_set);
        process(ctx.buffer);
    }
    
    for (i = 0; i < 8; i++) 
        hash[i] = ctx.h[i];
}

// Process a block
static void process(uint8_t *data)
{
    uint32_t t;
    uint32_t a, b, c, d, e, f, g, h, T1, T2;

    uint32_t block[16] = {0};
    create_block(data, block);
    uint32_t W[16]; //Message Schedule

    for (t = 0; t < 16; t++)
        W[t] = block[t];

    a = ctx.h[0];
    b = ctx.h[1];
    c = ctx.h[2];
    d = ctx.h[3];
    e = ctx.h[4];
    f = ctx.h[5];
    g = ctx.h[6];
    h = ctx.h[7];
    
    for (t = 0; t < 64; t++) {
        if (t >= 16) {
            W[t & 15] = small_sigma1(W[(t-2) & 15]) + 
                        W[(t-7) & 15] + 
                        small_sigma0(W[(t-15) & 15]) +
                        W[(t-16) & 15];
        }

        // Create woorking variables
        T1 = h + big_sigma1(e) + Ch(e,f,g) + K[t] + W[t & 15];
        T2 = big_sigma0(a) + Maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    ctx.h[0] += a;
    ctx.h[1] += b;
    ctx.h[2] += c;
    ctx.h[3] += d;
    ctx.h[4] += e;
    ctx.h[5] += f;
    ctx.h[6] += g;
    ctx.h[7] += h;
}

// create a block
static void create_block(const uint8_t *message, uint32_t *block)
{
    int b, w;
    uint32_t word;

    for (b = 0, w = 0; b < 64; b += 4, w++) {
        word = ((uint32_t)message[b]    << 24) | 
               ((uint32_t)message[b+1]  << 16) |
               ((uint32_t)message[b+2]  <<  8) |
                (uint32_t)message[b+3];
        block[w] = word;
    }
}

// Functions that build message schedule
inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ ((~x) & z);
}

inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

// Rotation functions
static inline uint32_t Rotr(uint32_t x, int n)
{
    return ((x >> n)) | (x << (32 - n));
}

static inline uint32_t big_sigma0(uint32_t x)
{
    return Rotr(x,2) ^ Rotr(x,13) ^ Rotr(x,22);
}

static inline uint32_t big_sigma1(uint32_t x)
{
    return Rotr(x,6) ^ Rotr(x,11) ^ Rotr(x,25);
}

static inline uint32_t small_sigma0(uint32_t x)
{
    return Rotr(x,7) ^ Rotr(x,18) ^ (x >> 3);
}

static inline uint32_t small_sigma1(uint32_t x)
{
    return Rotr(x,17) ^ Rotr(x,19) ^ (x >> 10);
}

