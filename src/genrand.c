#include <stdlib.h>
#include <time.h>

unsigned int gen_initseq(void) {
    int min = 0;
    int max = 42949672;
    srand((unsigned int)time(NULL) + rand());
    return min + (unsigned int)(rand() * (max - min + 1.0) / (1.0 + RAND_MAX));
}


unsigned int gen_sport(void) {
    int min = 49152;
    int max = 65535;
    srand((unsigned int)time(NULL) + rand());
    return min + (unsigned int)(rand() * (max - min + 1.0) / (1.0 + RAND_MAX));    
}