#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

// =============== Debug Utils ==============

void dump_hash(uint8_t *hash) {
    for (int i = 0; i < 32; i++) {
        printf("%x", hash[i]);
        
        if (i == 31) {
            printf("\n");
        }
    }
}

void print_with_color(char *str, char *color) {
    if (!strcmp(color, "red")) {
        printf("\x1b[31m%s: \033[m", str);
    } else if (!strcmp(color, "green")) {
        printf("\x1b[32m%s: \033[m", str);
    } else {
        fputs(str, stdout);
    }
}

void evaluate_elapsed_time(double *time) {
    *time = (double)clock();
}

void dump_elapsed_time(double time) {
    FILE *log_fp;
    char out[100] = "";
    char timestr[20];

    if ((log_fp = fopen("elapsed_time.txt", "a")) == NULL) {
        perror("Failed to open log file");
    }

    snprintf(timestr, 100, "%f", time / CLOCKS_PER_SEC);
    strcat(timestr, " + ");
    strcat(out, timestr);

    if (fwrite(out, strlen(out), 1, log_fp) < 0) {
        perror("Failed to write to log file");
    }

    fclose(log_fp);

    return;
}

// =============== String Ops Utils ==============

void create_full_path(char *dir, char *filename, char output[200]) {
    memcpy((void*)&(output[0]), (void*)dir, strlen(dir));
    output[strlen(dir)+1] = '\0';
    strcat(output, filename);
}

// =============== Standard Input Utils ==============

int check_param(char *param) {
    return (strcmp(param, "-i") && strcmp(param, "-c"));
}

// =============== Test Utils ==============