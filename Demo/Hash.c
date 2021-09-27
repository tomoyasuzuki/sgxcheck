// #include "Enclave_t.h"
// #include "string.h"
// #include "stdio.h"
// #include "sgx_tcrypto.h"
// #include "stdlib.h"
// #include "sgx_tseal.h"

// #define TABLE_SIZE 100
// #define HASH_SIZE 32
// #define MAX_PATH_LENGTH 200
// #define MAC "MAC"

// struct hash_data {
//     uint8_t hash[32];
// };

// struct hash_data *hash_list;

// int unseal_data(uint8_t *sealed_data, uint32_t data_size, uint8_t *unsealed_hash);
// int get_hash_index(char *str, int table_size);

// void untrusted_printf(char *str) {
//     o_printf(str, strlen(str));
// }

// int get_index(char *path) {
//     return get_hash_index(path, TABLE_SIZE);
// }

// // Generate hash_list index
// int get_hash_index(char *str, int table_size) {
//     int i = 0;
//     uint64_t sum = 0;

//     while(str[i] != '\0') {
//         sum += (uint64_t)str[i];
//         i++;
//     }

//     return sum % table_size;
// }

// // Check hash value
// void init_hash_list() {
//     hash_list = malloc(sizeof(struct hash_data) * TABLE_SIZE);
// }

// int cmp_hash(char *path, uint8_t *sealed_hash, size_t sh_size) {
//     uint8_t new_hash[HASH_SIZE];
//     uint8_t old_hash[HASH_SIZE];

//     memcpy(new_hash, hash_list[get_index(path)].hash, HASH_SIZE);

//     if (!unseal_data(sealed_hash, sh_size, old_hash)) {
//         untrusted_printf("Failed to unseal hash\n");
//         return 0;
//     }

//     return !memcmp(new_hash, old_hash, HASH_SIZE) ? 1 : 0; 
// }

// // Check hash value
// int cmp_hash_debug(char *path, uint8_t *new_hash, uint8_t *sealed_hash, uint32_t sh_size) {
//     uint8_t *old_hash = malloc(HASH_SIZE);

//     if (!unseal_data(sealed_hash, sh_size, old_hash)) {
//         untrusted_printf("Failed to unseal hash\n");
//         return 0;
//     }

//     return  !memcmp(new_hash, old_hash, HASH_SIZE) ? 1 : 0;
// }

// void calc_hash(char *path, void *buf, size_t buf_size) {
//     sgx_sha_state_handle_t state = NULL;
//     sgx_sha256_hash_t hash;
//     sgx_status_t err;
    
//     sgx_sha256_init(&state);

//     err = sgx_sha256_msg(buf, buf_size, &hash);

//     if (err == SGX_SUCCESS) {
//         memcpy(hash_list[get_index(path)].hash, hash, HASH_SIZE);
//     } 
//     sgx_sha256_close(state);
// }


// void calc_hash_debug(char *path, void *buf, size_t buf_size, uint8_t *dst) {
//     sgx_sha_state_handle_t state = malloc(sizeof(sgx_sha_state_handle_t));
//     sgx_sha256_hash_t hash;
//     sgx_status_t err;
    
//     sgx_sha256_init(state);

//     err = sgx_sha256_msg(buf, buf_size, &hash);

//     if (err == SGX_SUCCESS) {
//         memcpy(dst, hash, HASH_SIZE);
//         memcpy(hash_list[get_index(path)].hash, hash, HASH_SIZE);
//     } else {
//         untrusted_printf("Failed to calculate hash\n");
//     }
// }

// void get_hash(char *path, uint8_t *hash) {
//     int index = get_hash_index(path, TABLE_SIZE);
//     memcpy(hash, hash_list[index].hash, HASH_SIZE);
// }