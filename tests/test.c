#include "../include/sha.h"
#include <string.h>
#include <stdio.h>

// #define BUFF_LIMIT 4096
#define BUFF_LIMIT 262144

int main()
{
    int i;
    const uint8_t message[56] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint32_t hash_buffer[8] = {0};

    sha256_init();

    sha256_update(message, sizeof(message));

    sha256_final(hash_buffer);

    printf("hashed message: ");
    for (i = 0; i < 8; i++)
        printf("%08x", hash_buffer[i]);
    printf("\n");

    // int i;
    // uint32_t hash_buffer[8] = {0};
    // uint8_t buffer[BUFF_LIMIT] = {0};
    // FILE *fp;
    // const char *file_name = "../../Downloads/ubuntu-24.04.3-desktop-amd64.iso";

    // fp = fopen(file_name, "rb");
    // if (fp == NULL) {
    //     fprintf(stderr, "File open failed.\n");
    //     return -1;
    // }

    // sha256_init();

    // size_t n;
    // while ((n = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
    //     sha256_update(buffer, n);
    // }

    // sha256_final(hash_buffer);

    // printf("hashed message: ");
    // for (i = 0; i < 8; i++)
    //     printf("%08x", hash_buffer[i]);
    // printf("\n");

    // fclose(fp);
    return 0;
}

/* 
    Hash test:
    file: ubuntu-24.04.3-desktop-amd64.iso 
    hash: faabcf33ae53976d2b8207a001ff32f4e5daae013505ac7188c9ea63988f8328

    // Add more tests
*/
