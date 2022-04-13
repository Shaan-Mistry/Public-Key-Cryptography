#include <stdint.h>
#include <gmp.h>
#include <stdlib.h>

gmp_randstate_t state;

/* Initializes a global random state with a Mersenne Twister alogirthm. */
void randstate_init(uint64_t seed) {

    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);
    srandom(seed);
}

/* Frees all mempory used by the global random state. */
void randstate_clear(void) {
    gmp_randclear(state);
}
