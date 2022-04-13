#include "rsa.h"
#include "randstate.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <gmp.h>

/* Display  program synopsis and usage. */
void usage(char *exec) {
    fprintf(stderr,
        "SYNOPSIS\n"
        "   Generates an RSA public/private key pair.\n"
        "\n"
        "USAGE\n"
        "   %s [-hv] [-b bits] -n pbfile -d pvfile\n"
        "\n"
        "OPTIONS\n"
        "   -h              Display program help and usage.\n"
        "   -v              Display verbose program output.\n"
        "   -b bits         Minimum bits needed for public key n.\n"
        "   -c confidence   Miller-Rabin iterations for testing primes (default: 50).\n"
        "   -h              Public key file (default: rsa.pub).\n"
        "   -q              Private key file (default: rsa.priv).\n"
        "   -s seed         Random seed for testing.\n",
        exec);
}

/* Prints verbose output. */
void print_verbose(char *username, mpz_t s, mpz_t p, mpz_t q, mpz_t n, mpz_t e, mpz_t d) {
    printf("user = %s\n", username);
    gmp_printf("s (%zu bits) = %Zd\n", mpz_sizeinbase(s, 2), s);
    gmp_printf("p (%zu bits) = %Zd\n", mpz_sizeinbase(p, 2), p);
    gmp_printf("q (%zu bits) = %Zd\n", mpz_sizeinbase(q, 2), q);
    gmp_printf("n (%zu bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
    gmp_printf("e (%zu bits) = %Zd\n", mpz_sizeinbase(n, 2), e);
    gmp_printf("d (%zu bits) = %Zd\n", mpz_sizeinbase(n, 2), d);
}

int main(int argc, char **argv) {

    uint64_t nbits = 256; // Default minimum bits.
    uint64_t iters = 50; // Default number of Miller-Rabin iterations.
    uint64_t seed = time(NULL);
    FILE *pbfile = fopen("rsa.pub", "w");
    FILE *pvfile = fopen("rsa.priv", "w");
    bool verbose = false;
    int opt;

    /* Parse command-line options. */
    while ((opt = getopt(argc, argv, "b:i:n:d:s:vh")) != -1) {
        switch (opt) {
        case 'b': nbits = atoi(optarg); break;
        case 'i': iters = atoi(optarg); break;
        case 'n': pbfile = fopen(optarg, "w"); break;
        case 'd': pvfile = fopen(optarg, "w"); break;
        case 's': seed = atoi(optarg); break;
        case 'v': verbose = true; break;
        case 'h': usage(argv[0]); return 0;
        default: break;
        }
    }

    /* Check that the pbfile and pvfile are valid. */
    if (pbfile == NULL || pvfile == NULL) {
        fprintf(stderr, "Invalid public key file and/or private key file.\n");
        return 1;
    }

    /* Set private key file permissions. */
    int fd = fileno(pvfile);
    fchmod(fd, 0600);

    /* Initialize the random state. */
    randstate_init(seed);

    /* Get the current user's name as a string. */
    char *username_str;
    username_str = getenv("USER");

    /* Convert username to an mpz_t. */
    mpz_t username;
    mpz_init(username);
    mpz_set_str(username, username_str, 62);

    /* Make the public key */
    mpz_t p, q, n, e;
    mpz_inits(p, q, n, e, NULL);
    rsa_make_pub(p, q, n, e, nbits, iters);

    /* Make the private key. */
    mpz_t d;
    mpz_init(d);
    rsa_make_priv(d, e, p, q);

    /* Compute signiture of the username. */
    mpz_t s;
    mpz_init(s);
    rsa_sign(s, username, d, n);

    /* Write the generated public key to pbfile. */
    rsa_write_pub(n, e, s, username_str, pbfile);

    /* Write the generated private key to pvfile. */
    rsa_write_priv(n, d, pvfile);

    /* If verbose is enabled, print verbose output. */
    if (verbose) {
        print_verbose(username_str, s, p, q, n, e, d);
    }

    /* Close public and private key files */
    fclose(pbfile);
    fclose(pvfile);

    /* Clear the random state. */
    randstate_clear();

    /* Clear all mpz_t variables */
    mpz_clears(username, p, q, n, e, d, s, NULL);

    return 0;
}
