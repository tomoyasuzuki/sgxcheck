
#include <stdint.h>
#include <stdio.h>

int get_hash_index(char *str);
int calc_hash(void *data, size_t dsize, int type);
int cmp_hash(char *data, size_t dsize, void *old_hash);
void dump_hash_demo(char *hash, int len);