#include "Enclave_u.h"
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sgx_urts.h>
#include <dirent.h>
#include "utils.h"

#define MAX_FILE_NUMS 5
#define MAX_FILE_SIZE 104 * 1024 * 500
#define HASH_SIZE 32

sgx_enclave_id_t eid = 100;
int file_nums = 0;
char *dir_path = "/usr/bin/";
char *type = "-c";
char target_files[MAX_FILE_NUMS][200] = {"/usr/bin/ls", 
                                         "/usr/bin/ps", 
                                         "/usr/bin/apt", 
                                         "/usr/bin/x86_64-linux-gnu-strip", 
                                         "/usr/bin/utmpdump"};

// ======= utils ==============

void o_printf(char *str, int size) {
    printf(str);
}

void o_printf_d(char *str, int d) {
    printf("out: %s %d\n", str, d);
}

void o_strcat(char *dst, size_t d_size, char *src, size_t s_size) {
    strcat(dst, src);
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

        if (i == MAX_FILE_NUMS)
            break;
    }
}

void get_file_hash(int i) {
    FILE *fp;
    struct stat st;
    void *buf;
    uint8_t hash[32];
    uint8_t old_hash[32];
    sgx_status_t err;
    char *path = target_files[i];

    if ((fp = fopen(path,  "r")) == NULL) {
        print_with_color(path, "red");
        printf("Failed to open file\n");
        perror("error");
        return;
    }

    stat(path, &st);
    buf = malloc(st.st_size);

    fread(buf, st.st_size, 1, fp);

    err = calc_hash(eid, path, buf, st.st_size, hash);

    if (err == SGX_SUCCESS) {
        print_with_color(path, "green");
        dump_hash(hash);
    } else {
        print_with_color(path, "red");
        printf("Failed to get hash, error code=%x\n", err);
    }

    fclose(fp);
    free(buf);
}

void get_all_file_hashes() {
    printf("========== Calculating hash value ==========\n");

    for (int i = 0; i < 5; i++) {
        get_file_hash(i);
    }
}


void check_hash(int i) {
    sgx_status_t err;
    FILE *fp;
    struct stat st;
    void *file_buf;
    uint8_t new_hash[32];
    uint8_t old_hash[32];
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

    err = calc_hash(eid, path, file_buf, st.st_size, new_hash);
    err = get_hash(eid, path, old_hash);

    if (err == SGX_SUCCESS) {
        if (!memcmp(new_hash, old_hash, HASH_SIZE)) {
            print_with_color(path, "green");
            printf("file not broken\n");
        } else {
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

    for (int i = 0; i < 5; i++) {
        check_hash(i);
    }
}


int main(int argc, char **argv) {
    sgx_status_t err;

    if (argc > 1) {
        if (strcmp(argv[1], "-i") && strcmp(argv[1], "-c")) {
            exit(1);
        } else {
            type = argv[1];
        }
    }

    init_enclave();

    if ((err = init_hash_list(eid)) != SGX_SUCCESS) {
        print_with_color("SGX_ERROR: ", "red");
        printf("Failed to init hash table, code=%x\n", err);
        exit(1);
    }

    if (!strcmp(type, "-i")) {
        get_all_file_hashes();
    } else {
        check_all_file_hash();
    }
}