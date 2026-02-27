// Source code for sha1
#include <../include/sha.h>
#include <sha_common.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// H constants
static const uint32_t H[5] = {
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
};

// K constants
static const uint32_t K[4] = {
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
};

// hash state struct 
typedef struct {
    uint32_t h[5]; // current hash state (H0 .. H4)
    uint64_t total_len; // total message length in bytes
    uint8_t buffer[64]; // stores partial block
    uint32_t buffer_len; // number of bytes currently in buffer
} SHA1_CTX ;

// Initialise hash state variable
static SHA1_CTX ctx;

// Preprocessing Functions
static void create_block(const uint8_t *message, uint32_t *block);
static void process(uint8_t *data);

// Bit manipulation functions

// Initialise context state struct
void sha1_init(void)
{
    ctx.h[0] = H[0];
    ctx.h[1] = H[1]; 
    ctx.h[2] = H[2]; 
    ctx.h[3] = H[3]; 
    ctx.h[4] = H[4]; 
    ctx.buffer_len = 0;
    ctx.total_len = 0;
    memset(ctx.buffer, 0, 64);
}

// Process the blocks
void sha1_update(const uint8_t *data, size_t len)
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
void sha1_final(uint32_t *hash)
{
    int i;
    
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
