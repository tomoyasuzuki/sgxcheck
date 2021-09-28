#include "utils.h"
#include <stdio.h>
#include <string.h>

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

void create_full_path(char *dir, char *filename, char output[200]) {
    memcpy((void*)&(output[0]), (void*)dir, strlen(dir));
    output[strlen(dir)+1] = '\0';
    strcat(output, filename);
}