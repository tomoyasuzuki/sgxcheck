#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include "Hash.h"

#define MAX_FILE_NUMS 2000
#define MAX_FILE_SIZE 104 * 1024 * 500
#define HASH_SIZE 32

int file_nums = 0;
char *type = "-c";
int debug = 0;
char target_files[MAX_FILE_NUMS][200];

void print_with_color(char *str, char *color) {
    if (!strcmp(color, "red")) {
        printf("\x1b[31m%s: \033[m", str);
    } else if (!strcmp(color, "green")) {
        printf("\x1b[32m%s: \033[m", str);
    } else {
        fputs(str, stdout);
    }
}

void get_hash_file_path(char *path, char *hash_path) {
    int index = get_hash_index(path);
    snprintf(hash_path, 100, "%d", index);
    strcat(hash_path, path);
}

void get_file_hash(int i) {
    FILE *fp;
    struct stat st;
    void *buf;
    int err;
    char *path = target_files[i];

    if ((fp = fopen(path,  "r")) == NULL) {
        print_with_color(path, "red");
        printf("Failed to open file\n");
        return;
    }

    stat(path, &st);
    buf = malloc(st.st_size);

    fread(buf, st.st_size, 1, fp);

    err = calc_hash(path, buf, st.st_size, debug);

    fclose(fp);
    free(buf);

    return;
}

void interval(double num) {
    clock_t t;
    t = num * CLOCKS_PER_SEC + clock();
    while(t > clock());
}

void get_all_file_hashes() {
    printf("========== Calculating hash value ==========\n");

    for (int i = 0; i < MAX_FILE_NUMS; i++) {
        get_file_hash(i);
    }
}

void check_hash(int i) {
    FILE *fp, *hash_fp;
    struct stat st, hash_st;
    int err;
    void *file_buf, *old_hash;
    char hash_path[100];
    char *path;

    path = target_files[i];

    // Open data file
    if ((fp = fopen(path, "r")) == NULL) {
        print_with_color(path, "red");
        printf("Failed to open file\n");
        return;
    }
    // Open hash file
    get_hash_file_path(path, hash_path);

    if ((hash_fp = fopen(hash_path, "r")) == NULL) {
        print_with_color(hash_path, "red");
        printf("Failed to open file\n");
        return;
    }

    // Get File size
    stat(path, &st);
    stat(hash_path, &hash_st);

    file_buf = malloc(st.st_size);
    old_hash = malloc(hash_st.st_size);

    fread(file_buf, st.st_size, 1, fp);
    fread(old_hash, hash_st.st_size, 1, hash_fp);

    err = cmp_hash(file_buf, st.st_size, old_hash);

    if (err) {
        print_with_color(path, "green");
        printf("file not broken\n");
    } else {
        print_with_color(path, "red");
        printf("file broken!!!.\n");
    }
    
    fclose(fp);
    fclose(hash_fp);
    free(file_buf);

    return;
}

void check_all_file_hash() {
    printf("========== Checking hash value ==========\n");

    for (int i = 0; i < MAX_FILE_NUMS; i++) {
        check_hash(i);
    }
}

int check_param(char *param) {
    return (strcmp(param, "-i") && strcmp(param, "-c"));
}

void create_dummy_files() {
    for (int i = 0; i < MAX_FILE_NUMS; i++) {
        char path[100] = "demo";
        char num[5];
        snprintf(num, 5, "%d", i);
        strcat(path, num);

        FILE *fp = fopen(path, "w");
        fwrite(path, strlen(path), 1, fp);
        fclose(fp);
        memcpy(target_files[i], path, strlen(path));
    }
}

int main(int argc, char **argv) {
    int err;
    double time;

    if (argc > 1) {
        if (check_param(argv[1])) {
            perror("Paramater Invalid");
        } else {
            type = argv[1];

            if (argv[2]) {
                if (!strcmp(argv[2], "-d")) {
                    debug = 1;
                }
            }
        }
    }

    create_dummy_files();

    if (!strcmp(type, "-i")) {
        get_all_file_hashes();
    } else if (!strcmp(type, "-c")) {
        check_all_file_hash();
    } else {
        perror("Paramater Invalid");
    }

    time = clock();
    FILE *timelog;
    timelog = fopen("demolog.txt", "a");
    if (timelog == NULL) {
        timelog = fopen("demolog.txt", "w");
    }
    char out[100] = "";
    char timestr[20];
    snprintf(timestr, 100, "%f", time / CLOCKS_PER_SEC);
    strcat(timestr, " + ");
    strcat(out, timestr);
    fwrite(out, strlen(out), 1, timelog);
    fclose(timelog);
    return 0;
}
