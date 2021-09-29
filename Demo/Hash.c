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

void dump_hash_demo(unsigned char *hash) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%x", hash[i]);

        if (i == (SHA256_DIGEST_LENGTH - 1)) {
            printf("\n");
            break;
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
    SHA256_CTX ctx;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, dsize);
    SHA256_Final(hash, &ctx);

    return !memcmp(old_hash, hash, SHA256_DIGEST_LENGTH) ? 1 : 0; 
}

void save_hash(char *path, unsigned char *hash) {
    FILE *fp;
    size_t wsize;
    char fullpath[100];
    snprintf(fullpath, 100, "%d", get_hash_index(path));
    strcat(fullpath, path);

    if ((fp = fopen(fullpath, "w")) == NULL) {
        perror("Error");
        return;
    }

    if ((wsize = fwrite(hash, SHA256_DIGEST_LENGTH, 1, fp)) < 1) {
        perror("Error");
        return;
    }

    printf("%s: ", path);
    printf("Successed to save hash file.\n");

    fclose(fp);

    return;
}

int calc_hash(char *path, void *data, size_t dsize, int type) {
    SHA256_CTX ctx;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, dsize);
    SHA256_Final(hash, &ctx);

    if (type) {
        printf("%s: ", path);
        dump_hash_demo(hash);
    } else {
        printf("%s: ", path);
        printf("Successed to calculate hash.\n");
    }

    save_hash(path, hash);

    return 1;
}