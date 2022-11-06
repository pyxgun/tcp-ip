#include <stdlib.h>
#include <time.h>
#include <stdint.h>

unsigned int gen_initseq(void) {
    int min = 0;
    int max = 42949672;
    srand((unsigned int)time(NULL));
    return min + (unsigned int)(rand() * (max - min + 1.0) / (1.0 + RAND_MAX));
}


unsigned int gen_sport(void) {
    int min = 49152;
    int max = 65535;
    srand((unsigned int)time(NULL));
    return min + (unsigned int)(rand() * (max - min + 1.0) / (1.0 + RAND_MAX));    
}


uint8_t random_byte(void) {
    int min = 0;
    int max = 255;
    return (uint8_t)(min + (unsigned int)(rand() * (max - min + 1.0) / (1.0 + RAND_MAX)));
}