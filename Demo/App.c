// #include "Enclave_u.h"
// #include <stdio.h>
// #include <stdint.h>
// #include <string.h>
// #include <stdlib.h>
// #include <unistd.h>
// #include <fcntl.h>
// #include <sys/types.h>
// #include <sys/stat.h>
// #include <sgx_urts.h>
// #include <dirent.h>
// #include "utils.h"
// #include "sgx_tseal.h"

// #define MAX_FILE_NUMS 4
// #define MAX_FILE_SIZE 104 * 1024 * 500
// #define HASH_SIZE 32

// sgx_enclave_id_t eid = 100;
// int file_nums = 0;
// char *dir_path = "/usr/bin/";
// char *type = "-c";
// int debug = 0;
// char target_files[MAX_FILE_NUMS][200] = { "./test1","./test2","./test3","./test4" };

// // ======= utils ==============

// void o_printf(char *str, int size) {
//     printf(str);
// }

// // ======= enclave ops ========

// void init_enclave() {
//     char *enc_img_name = "enclave.signed.so";

//     sgx_launch_token_t token = {0};
//     sgx_status_t d = SGX_ERROR_UNEXPECTED;
//     int token_updated = 0;

//     if ((d = sgx_create_enclave(
//                         enc_img_name, 
//                         SGX_DEBUG_FLAG, 
//                         &token, 
//                         &token_updated, 
//                         &eid, NULL)) != SGX_SUCCESS) {

//         printf("Error: failed to create Enclave, error code=%x.\n", d);
//         exit(1);
//     }

//     return;
// }

// void  get_all_files(char *path) {
//     DIR *dir;
//     struct dirent *dent;

//     dir = opendir(path);

//     printf("Directory ==> %s\n", path);

//     int i = 0;
//     for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
//         int j = 0;

//         do {
//             target_files[i][j] = dent->d_name[j];
//             j++;
//         } while(dent->d_name[j] != '\0');

//         target_files[i][j] = '\0';

//         printf("%d: %s\n",i, target_files[i]);
        
//         i++;
//         file_nums = i;

//         if (i == MAX_FILE_NUMS)
//             break;
//     }
// }

// void get_file_hash(int i) {
//     FILE *fp, *sealed_hash_fp;
//     struct stat st;
//     void *buf;
//     uint8_t hash[32];
//     uint8_t old_hash[32];
//     uint32_t sealed_data_size;
//     uint8_t *sealed_buf;
//     int seal_err;
//     sgx_status_t err;
//     char *path = target_files[i];

//     if ((fp = fopen(path,  "r")) == NULL) {
//         print_with_color(path, "red");
//         printf("Failed to open file\n");
//         perror("error");
//         return;
//     }

//     stat(path, &st);
//     buf = malloc(st.st_size);

//     fread(buf, st.st_size, 1, fp);

//     if (debug) {
//         if ((err = calc_hash_debug(eid, path, buf, st.st_size, hash)) != SGX_SUCCESS) {
//             print_with_color(path, "red");
//             printf("Failed to calculate hash value, code=%x\n", err);
//             return;
//         }
//     } else {
//         if ((err = calc_hash(eid, path, buf, st.st_size)) != SGX_SUCCESS) {
//             print_with_color(path, "red");
//             printf("Failed to calculate hash value, code=%x\n", err);
//             return;
//         }
//     }
    

//     if (err == SGX_SUCCESS) {
//         if (debug)
//             print_with_color("[DEBUG]", "green");
        
//         print_with_color(path, "green");

//         if (debug) {
//             dump_hash(hash);
//         } else {
//             printf("Successed to calculate hash.\n");
//         }
//     } else {
//         print_with_color(path, "red");
//         printf("Failed to get hash, error code=%x\n", err);
//     }

//     if ((err = get_sealed_data_size(eid, &sealed_data_size, path)) != SGX_SUCCESS) {
//         print_with_color(path, "red");
//         printf("Failed to get sealed data size, code=%x\n", err);
//     }

//     sealed_buf = malloc(sealed_data_size);

//     if ((err = seal_data(eid, &seal_err, path, sealed_buf, sealed_data_size)) != SGX_SUCCESS) {
//         print_with_color(path, "red");
//         printf("Failed to get sealed data size, code=%x\n", err);
//     }

//     int index = 0;
//     char hash_path[100];

//     err = get_index(eid, &index, path);

//     snprintf(hash_path, 100, "%d", index);

//     if ((sealed_hash_fp = fopen(hash_path, "w")) == NULL) {
//         print_with_color(path, "red");
//         printf("Failed to create sealed_hash_file\n");
//     }

//     size_t wsize = fwrite(sealed_buf, sealed_data_size, 1, sealed_hash_fp);
//     if (wsize < 1) {
//         print_with_color(path, "red");
//         printf("Failed to write sealed_hash\n");
//     }

//     fclose(fp);
//     free(buf);

//     return;
// }

// void get_all_file_hashes() {
//     printf("========== Calculating hash value ==========\n");

//     for (int i = 0; i < MAX_FILE_NUMS; i++) {
//         get_file_hash(i);
//     }
// }

// void check_hash(int i) {
//     sgx_status_t err;
//     FILE *fp, *hash_fp;
//     struct stat fpst,hash_fpst;
//     char *path = target_files[i];
//     int index;
//     char hash_path[100];
//     void *file_buf;
//     uint8_t new_hash[HASH_SIZE];
//     uint8_t *sealed_hash;
//     uint32_t sealed_data_size;
//     int cmp_err;

//     if ((fp = fopen(path, "r")) == NULL) {
//         print_with_color(path, "red");
//         printf("Failed to open file\n");
//         return;
//     }

//     if (i == 3) {
//         fwrite("hoge", strlen("hoge"), 1, fp);
//         fflush(fp);
//     }

//     err = get_index(eid, &index, path);
//     snprintf(hash_path, 100,"%d", index);

//     if ((hash_fp = fopen(hash_path, "r+")) == NULL) {
//         print_with_color(hash_path, "red");
//         printf("Failed to open file\n");
//         return;
//     }

//     stat(path, &fpst);
//     stat(hash_path, &hash_fpst);
    
//     if (fpst.st_size > MAX_FILE_SIZE) {
//         printf("%s: File size is too big ...\n", path); 
//         fclose(fp);
//         return;
//     }
    
//     file_buf = malloc(fpst.st_size);
//     sealed_hash = malloc(hash_fpst.st_size);

//     fread(file_buf, fpst.st_size, 1, fp);
//     fread(sealed_hash, hash_fpst.st_size, 1, hash_fp);

//     err = calc_hash(eid, path, file_buf, fpst.st_size);
//     err = cmp_hash(eid, &cmp_err, path, sealed_hash, (uint32_t)hash_fpst.st_size);

//     if (cmp_err) {
//         print_with_color(path, "green");
//         printf("File not broken.\n");
//     } else {
//         print_with_color(path, "red");
//         printf("File broken!!\n");
//     }

//     free(file_buf);
//     fclose(fp);
//     fclose(hash_fp);

//     return;
// }


// void check_hash_debug(int i) {
//     sgx_status_t err;
//     FILE *fp;
//     struct stat st;
//     void *file_buf;
//     uint8_t new_hash[HASH_SIZE];
//     uint8_t old_hash[HASH_SIZE];
//     char *path = target_files[i];

//     if ((fp = fopen(path, "r")) == NULL) {
//         print_with_color(path, "red");
//         printf("Failed to open file\n");
//         return;
//     }

//     stat(path, &st);

//     if (st.st_size > MAX_FILE_SIZE) {
//         printf("%s: File size is too big ...\n", path);
//         fclose(fp);
//         return;
//     }

//     file_buf = malloc(st.st_size);

//     fread((void*)file_buf, (uint32_t)st.st_size, 1, fp);

//     err = calc_hash_debug(eid, path, file_buf, st.st_size, new_hash);
//     err = get_hash(eid, path, old_hash);

//     if (err == SGX_SUCCESS) {
//         if (!memcmp(new_hash, old_hash, HASH_SIZE)) {
//             memset(old_hash, 0, HASH_SIZE);
//             memset(new_hash, 0, HASH_SIZE);
//             print_with_color(path, "green");
//             printf("file not broken\n");
//         } else {
//             memset(old_hash, 0, HASH_SIZE);
//             memset(new_hash, 0, HASH_SIZE);
//             print_with_color(path, "red");
//             printf("file broken!!!\n");
//             printf("Hash_new: ");
//             dump_hash(new_hash);
//             printf("Hash_old: ");
//             dump_hash(old_hash);
//         }
//     } else {
//         print_with_color(path, "red");
//         printf("Failed to get hash.\n");
//     }
    
//     fclose(fp);
//     free(file_buf);
// }

// void check_all_file_hash() {
//     printf("========== Checking hash value ==========\n");

//     for (int i = 0; i < MAX_FILE_NUMS; i++) {
//         if (debug) {
//             check_hash_debug(i);
//         } else {
//             check_hash(i);
//         }
//     }
// }

// int check_param(char *param) {
//     return (strcmp(param, "-i") && strcmp(param, "-c"));
// }

// int main(int argc, char **argv) {
//     sgx_status_t err;
//     if (argc > 1) {
//         if (check_param(argv[1])) {
//             perror("Paramater Invalid");
//         } else {
//             type = argv[1];

//             if (argv[2]) {
//                 if (!strcmp(argv[2], "-d")) {
//                     debug = 1;
//                 }
//             }
//         }
//     }

//     init_enclave();

//     if ((err = init_hash_list(eid)) != SGX_SUCCESS) {
//         print_with_color("SGX_ERROR: ", "red");
//         printf("Failed to init hash table, code=%x\n", err);
//         exit(1);
//     }

//     if (!strcmp(type, "-i")) {
//         get_all_file_hashes();
//     } else if (!strcmp(type, "-c")) {
//         check_all_file_hash();
//     } else {
//         perror("Paramater Invalid");
//     }

//     return 0;
// }
