#include <stdint.h>

void dump_hash(uint8_t *hash);
void print_with_color(char *str, char *color);
void evaluate_elapsed_time(double *time);
void dump_elapsed_time(double time);
int check_param(char *param);
void create_full_path(char *dir, char *filename, char output[]);