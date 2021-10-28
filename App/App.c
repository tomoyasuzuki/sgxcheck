#include "Enclave_u.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sgx_urts.h>
#include <time.h>
#include <dirent.h>
#include "utils.h"
#include "sgx_tseal.h"

#define MAX_FILE_NAME_LENGTH 200
#define MAX_FILE_NUMS 1000
#define MAX_FILE_SIZE 104 * 1024 * 500
#define HASH_SIZE 32

sgx_enclave_id_t eid = 100;

char *type = "-c";
int debug = 0;
int file_nums = 0;
char target_files[MAX_FILE_NUMS][MAX_FILE_NAME_LENGTH];

// ======= utils ==============

void o_printf(char *str, int size) {
    printf("%s", str);
}

void ocall_dump_hash(uint8_t *hash) {
    dump_hash(hash);
}

// ======= enclave ops ========

void init_enclave() {
    char *enc_img_name = "enclave.signed.so";

    sgx_launch_token_t token = {0};
    sgx_status_t d = SGX_ERROR_UNEXPECTED;
    int token_updated = 0;

    if ((d = sgx_create_enclave(
                        enc_img_name, 
                        SGX_DEBUG_FLAG, 
                        &token, 
                        &token_updated, 
                        &eid, NULL)) != SGX_SUCCESS) {

        printf("Error: failed to create Enclave, error code=%x.\n", d);
        exit(1);
    }

    return;
}

void  get_all_files(char *path) {
    DIR *dir;
    struct dirent *dent;

    dir = opendir(path);

    printf("Directory ==> %s\n", path);

    int i = 0;
    for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
        int j = 0;

        do {
            target_files[i][j] = dent->d_name[j];
            j++;
        } while(dent->d_name[j] != '\0');

        target_files[i][j] = '\0';

        printf("%d: %s\n",i, target_files[i]);
        
        i++;
        file_nums = i;

        if (i == file_nums)
            break;
    }
}

void print_error_with_path(char *path, char *msg) {
    print_with_color(path, "red");
    printf("%s", msg);
}

size_t get_file_size(char *path) {
    struct stat st;
    stat(path, &st);
    return (size_t)st.st_size;
}

void get_file_hash(int i) {
    FILE *fp, *sealed_hash_fp;
    size_t f_size;
    uint8_t hash[HASH_SIZE];
    uint8_t old_hash[HASH_SIZE];
    uint32_t sealed_buf_size;
    uint8_t *sealed_buf;
    sgx_status_t err;
    int retval;
    size_t wsize;
    char *path;
    int index;
    char hash_path[100];
    void *buf;

    path = target_files[i];

    if ((fp = fopen(path,  "r")) == NULL) {
        print_error_with_path(path, "Failed to open file\n");
        perror("Error");
        return;
    }

    f_size = get_file_size(path);
    buf = malloc(f_size);

    if (fread(buf, f_size, 1, fp) < 1) {
        print_error_with_path(path, "Failed to read file\n");
        return;
    }

    if ((err = get_sealed_data_size(eid, &sealed_buf_size)) != SGX_SUCCESS) {
        print_error_with_path(path, "Failed to get sealed data size\n");
        return;
    }

    sealed_buf = (uint8_t*)malloc(sealed_buf_size);

    if (debug) {
        if ((err = calc_hash_debug(eid, path, buf, f_size, hash)) != SGX_SUCCESS) {
            print_error_with_path(path, "[DEBUG]Failed to calculate hash value\n");
            return;
        }
    } else {
        if ((err = calc_hash(eid, &retval, path, buf, f_size, sealed_buf, sealed_buf_size)) != SGX_SUCCESS) {
            print_error_with_path(path, "Failed to calculate hash value\n");
            return;
        }
    }

    if (err == SGX_SUCCESS) {
        if (debug)
            print_with_color("[DEBUG]", "green");
        
        print_with_color(path, "green");

        if (debug) {
            dump_hash(hash);
        } else {
            printf("Successed to calculate hash.\n");
        }
    } else {
        print_with_color(path, "red");
        printf("Failed to get hash, error code=%x\n", err);
    }

    if ((err = get_index(eid, &index, path)) != SGX_SUCCESS) 
        return;

    snprintf(hash_path, 100, "%d", index);
    strcat(hash_path, path);

    if (debug)
        goto  clean;

    if ((sealed_hash_fp = fopen(hash_path, "w")) == NULL) {
        print_with_color(path, "red");
        printf("Failed to create sealed_hash_file\n");
    }

    if ((wsize = fwrite(sealed_buf, sealed_buf_size, 1, sealed_hash_fp)) < 1) {
        print_with_color(path, "red");
        printf("Failed to write sealed_hash\n");
    }

    clean:
        fclose(fp);
        free(buf);
        free(sealed_buf);

    return;
}

void get_all_file_hashes() {
    printf("========== Calculating hash value ==========\n");

    for (int i = 0; i < file_nums; i++) {
        get_file_hash(i);
    }
}

void check_hash(int i) {
    sgx_status_t err;
    FILE *fp, *hash_fp;
    size_t f_size, hashf_size;
    char *path = target_files[i];
    int index;
    char hash_path[100];
    void *file_buf;
    uint8_t *sealed_hash;
    uint32_t sealed_data_size;
    int retval;

    if ((fp = fopen(path, "r")) == NULL) {
        print_error_with_path(path, "Failed to open file\n");
        return;
    }

    if ((err = get_index(eid, &index, path)) != SGX_SUCCESS) {
        print_error_with_path(path, "Failed to get index\n");
        return;
    }

    snprintf(hash_path, 100,"%d", index);
    strcat(hash_path, path);

    if ((hash_fp = fopen(hash_path, "r")) == NULL) {
        print_error_with_path(hash_path, "Failed to open file\n");
        return;
    }

    f_size = get_file_size(path);
    hashf_size = get_file_size(hash_path);
    
    file_buf = malloc(f_size);
    sealed_hash = malloc(hashf_size);

    if (fread(file_buf, f_size, 1, fp) < 1) {
        print_error_with_path(path, "Failed to open file\n");
        return;
    }
    
    if (fread(sealed_hash, hashf_size, 1, hash_fp) < 1) {
        print_error_with_path(hash_path, "Failed to open file\n");
        return;
    }

    if ((err = cmp_hash(eid, 
                        &retval, 
                        file_buf, 
                        f_size, 
                        sealed_hash, 
                        hashf_size) != SGX_SUCCESS)) {
        print_error_with_path(path, "Failed to compare hash value\n");
        return;
    }

    if (retval != -1) {
        print_with_color(path, "green");
        printf("File not broken.\n");
    } else {
        print_error_with_path(path, "File broken!!\n");
    }

    free(file_buf);
    free(sealed_hash);
    fclose(fp);
    fclose(hash_fp);

    return;
}


void check_hash_debug(int i) {
    sgx_status_t err;
    FILE *fp;
    struct stat st;
    void *file_buf;
    uint8_t new_hash[HASH_SIZE];
    uint8_t old_hash[HASH_SIZE];
    char *path = target_files[i];

    if ((fp = fopen(path, "r")) == NULL) {
        print_with_color(path, "red");
        printf("Failed to open file\n");
        return;
    }

    stat(path, &st);

    if (st.st_size > MAX_FILE_SIZE) {
        printf("%s: File size is too big ...\n", path);
        fclose(fp);
        return;
    }

    file_buf = malloc(st.st_size);

    fread((void*)file_buf, (uint32_t)st.st_size, 1, fp);

    err = calc_hash_debug(eid, path, file_buf, st.st_size, new_hash);
    err = get_hash(eid, path, old_hash);

    if (err == SGX_SUCCESS) {
        if (!memcmp(new_hash, old_hash, HASH_SIZE)) {
            memset(old_hash, 0, HASH_SIZE);
            memset(new_hash, 0, HASH_SIZE);
            print_with_color(path, "green");
            printf("file not broken\n");
        } else {
            memset(old_hash, 0, HASH_SIZE);
            memset(new_hash, 0, HASH_SIZE);
            print_with_color(path, "red");
            printf("file broken!!!\n");
            printf("Hash_new: ");
            dump_hash(new_hash);
            printf("Hash_old: ");
            dump_hash(old_hash);
        }
    } else {
        print_with_color(path, "red");
        printf("Failed to get hash.\n");
    }
    
    fclose(fp);
    free(file_buf);
}

void check_all_file_hash() {
    printf("========== Checking hash value ==========\n");

    for (int i = 0; i < file_nums; i++) {
        if (debug) {
            check_hash_debug(i);
            //check_hash(i);
        } else {
            check_hash(i);
        }
    }
}

void add_dummy_filename(int num) {
    for (int i = 0; i <= num; i++) {
        char path[MAX_FILE_NAME_LENGTH] = "test";
        char n[20];
        snprintf(n, 6, "%d", i);
        strcat(path, n);
        memcpy(target_files[i], path, strlen(path));
    }
}

int main(int argc, char **argv) {
    sgx_status_t err;
    double time;

    if (argc > 1) {
        if (check_param(argv[1])) {
            printf("Error: Parameter Invalida\n");
            exit(1);
        } else {
            type = argv[1];

            if (argv[2]) {
                if (!strcmp(argv[2], "-d")) {
                    debug = 1;
                } else {
                    file_nums = atoi(argv[2]);
                }
            }

            if (argv[3]) {
                file_nums = atoi(argv[3]);
            }
        }
    }

    init_enclave();
    add_dummy_filename(file_nums);

    if (!strcmp(type, "-i")) {
        get_all_file_hashes();
    } else if (!strcmp(type, "-c")) {
        check_all_file_hash();
    } else {
        perror("Paramater Invalid");
    }

    if (debug) {
        evaluate_elapsed_time(&time);
        dump_elapsed_time(time);
    }

    return 0;
}
