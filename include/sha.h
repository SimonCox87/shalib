#ifndef SHA_H
#define SHA_H

#include <stdint.h>
#include <stdio.h>

void sha1_init(void);
void sha1_update(const uint8_t *data, size_t len);
void sha1_final(uint32_t *hash);

void sha256_init(void);
void sha256_update(const uint8_t *data, size_t len);
void sha256_final(uint32_t *hash);



#endif
