#include "Enclave_t.h"
#include "string.h"
#include "stdio.h"
#include "sgx_tcrypto.h"
#include "stdlib.h"

#define TABLE_SIZE 100
#define HASH_SIZE 32
#define MAX_PATH_LENGTH 200

struct hash_data {
    uint8_t hash[32];
};

struct hash_data *hash_list;

void untrusted_printf(char *str) {
    o_printf(str, strlen(str));
}

// Generate hash_list index
int get_hash_index(char *str, int table_size) {
    int i = 0;
    uint64_t sum = 0;

    while(str[i] != '\0') {
        sum += (uint64_t)str[i];
        i++;
    }

    return sum % table_size;
}

void init_hash_list() {
    hash_list = malloc(sizeof(struct hash_data) * TABLE_SIZE);
}

int cmp_hash(uint8_t *old, uint8_t *new, size_t size) {
    return memcmp((void*)old, (void*)new, size);
}

// Calculate SHA256 hash value
void calc_hash(char *path, void *buf, size_t buf_size, uint8_t *dst) {
    sgx_sha_state_handle_t state = malloc(1024 * 1024);
    sgx_sha256_hash_t hash;
    sgx_status_t err;
    
    sgx_sha256_init(state);

    err = sgx_sha256_msg(buf, buf_size, &hash);

    if (err == SGX_SUCCESS) {
        memcpy(dst, hash, HASH_SIZE);
    } else {
        o_printf_d("code", err);
    }

    int index = get_hash_index(path, TABLE_SIZE);
    
    memcpy(hash_list[index].hash, hash, HASH_SIZE);
}

void get_hash(char *path, uint8_t *hash) {
    int index = get_hash_index(path, TABLE_SIZE);
    memcpy(hash, hash_list[index].hash, HASH_SIZE);
}
