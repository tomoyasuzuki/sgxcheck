#include "Enclave_t.h"
#include "string.h"
#include "stdio.h"
#include "sgx_tcrypto.h"
#include "stdlib.h"
#include "sgx_tseal.h"

#define TABLE_SIZE 1000
#define HASH_SIZE 32
#define MAX_PATH_LENGTH 200
#define MAC "MAC"

int unseal_data(uint8_t *sealed_data, uint32_t data_size, uint8_t *unsealed_hash);
int get_hash_index(char *str, int table_size);
int sgx_sha256_calc(void *data, size_t dsize, uint8_t *dst);

void untrusted_printf(char *str) {
    o_printf(str, strlen(str));
}

int get_index(char *path) {
    return get_hash_index(path, TABLE_SIZE);
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

int cmp_hash(void *data, size_t dsize , uint8_t *sealed_hash, size_t sh_size) {
    uint8_t new_hash[HASH_SIZE];
    uint8_t old_hash[HASH_SIZE];

    if (sgx_sha256_calc(data, dsize, &(new_hash[0])) < 0)
        return -1;

    if (!unseal_data(sealed_hash, sh_size, &(old_hash[0]))) {
        return -1;
    }

    // TODO: fix allways return -1 bug
    return !memcmp(new_hash, old_hash, HASH_SIZE) ? 1 : -1; 
}

// Check hash value
int cmp_hash_debug(char *path, uint8_t *new_hash, uint8_t *sealed_hash, uint32_t sh_size) {
    uint8_t *old_hash = malloc(HASH_SIZE);

    if (!unseal_data(sealed_hash, sh_size, old_hash)) {
        untrusted_printf("Failed to unseal hash\n");
        return 0;
    }

    return  !memcmp(new_hash, old_hash, HASH_SIZE) ? 1 : 0;
}

int sgx_sha256_calc(void *data, size_t dsize, uint8_t *dst) {
    sgx_sha_state_handle_t state = NULL;
    sgx_sha256_hash_t hash;
    sgx_status_t err;

    if ((err = sgx_sha256_init(&state)) != SGX_SUCCESS) 
        return -1;

    if ((err = sgx_sha256_msg(data, dsize, (sgx_sha256_hash_t*)dst) != SGX_SUCCESS))
        return -1; 

    if ((err = sgx_sha256_close(state)) != SGX_SUCCESS)
        return -1;

    return 1;
}

int seal_hash(void *src, void *dst) {
    sgx_status_t err;

    if ((err = sgx_seal_data(strlen(MAC),
                            (const uint8_t *)MAC,
                            HASH_SIZE,
                            (const uint8_t *)src,
                            sgx_calc_sealed_data_size(strlen(MAC), HASH_SIZE),
                            (sgx_sealed_data_t *)dst) != SGX_SUCCESS)) {
        return -1;
    }

    return 1;
}

int calc_hash(char *path, void *buf, size_t buf_size, void *dst, uint32_t dst_size) {
    uint8_t hash[HASH_SIZE];

    if (path == NULL | buf == NULL | dst == NULL)
        return -1;
    
    if (sgx_sha256_calc(buf, buf_size, &hash[0])) {
        ocall_dump_hash(&hash[0]);
    } else {
        return -1;
    }

    if (seal_hash(&hash[0],dst) < 0)
        return -1;

    return 1;
}


void calc_hash_debug(char *path, void *buf, size_t buf_size, uint8_t *dst) {
    sgx_sha_state_handle_t state = malloc(sizeof(sgx_sha_state_handle_t));
    sgx_sha256_hash_t hash;
    sgx_status_t err;
    
    sgx_sha256_init(state);

    err = sgx_sha256_msg(buf, buf_size, &hash);

    if (err == SGX_SUCCESS) {
        memcpy(dst, hash, HASH_SIZE);
    } else {
        untrusted_printf("Failed to calculate hash\n");
    }
}

void get_hash(char *path, uint8_t *hash) {
    int index = get_hash_index(path, TABLE_SIZE);
    //memcpy(hash, hash_list[index].hash, HASH_SIZE);
}

uint32_t get_sealed_data_size() {
    return sgx_calc_sealed_data_size((uint32_t)sizeof(MAC), (uint32_t)HASH_SIZE);
}

int unseal_data(uint8_t *sealed_data, uint32_t data_size, uint8_t *unsealed_hash) {
    sgx_status_t err;
    uint32_t mac_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_data);
    uint32_t decrypt_data_len= sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_data);

    uint8_t *de_mac_text =(uint8_t *)malloc(mac_len);

    if ((err = sgx_unseal_data((const sgx_sealed_data_t *)sealed_data,
                                de_mac_text, 
                                &mac_len, 
                                unsealed_hash, 
                                &decrypt_data_len)) == SGX_SUCCESS) {
       return 1;
    } 

    return 0;
}