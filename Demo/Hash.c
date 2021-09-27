#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/sha.h>
#include "Hash.h"

#define TABLE_SIZE 100
#define HASH_SIZE 16
#define MAX_PATH_LENGTH 200
#define MAC "MAC"

void dump_hash_demo(char *hash, int len) {
    for (int i = 0; i < len; i++) {
        printf("%x", hash[i]);

        if (i == (len-1)) {
            printf("\n");
        }
    }
}

int get_hash_index(char *str) {
    int i = 0;
    uint64_t sum = 0;

    while(str[i] != '\0') {
        sum += (uint64_t)str[i];
        i++;
    }

    return sum % TABLE_SIZE;
}

int cmp_hash(char *data, size_t dsize, void *old_hash) {
    SHA256_CTX *ctx;

    SHA256_Init(ctx);
    SHA256_Update(ctx, data, dsize);

    return !memcmp(old_hash, ctx->data, HASH_SIZE) ? 1 : 0; 
}

int calc_hash(void *data, size_t dsize, int type) {
    SHA256_CTX ctx;
    unsigned char hash[SHA384_DIGEST_LENGTH];
    //char *hash = malloc(100);
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, dsize);
    SHA256_Final(hash, &ctx);
    //SHA256(data, dsize, hash);
    printf("HASH: ");
    dump_hash_demo(hash, SHA256_DIGEST_LENGTH);

    return 1;
}