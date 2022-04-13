#include "rsa.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <gmp.h>

/* Display  program synopsis and usage. */
void usage(char *exec) {
    fprintf(stderr,
        "SYNOPSIS\n"
        "   Decrypts data using RSA decryption.\n"
        "   Encrypted data is encrypted by the encrypt program.\n"
        "\n"
        "USAGE\n"
        "   %s [-hv] [-b bits] -n pbfile -d pvfile\n"
        "\n"
        "OPTIONS\n"
        "   -h              Display program help and usage.\n"
        "   -v              Display verbose program output.\n"
        "   -i infile       Input file of data to encrypt (default: stdin).\n"
        "   -o outfile      Output file for encrypted data (default: stdout).\n"
        "   -d pvfile       Public key file (default: rsa.pub).\n",
        exec);
}

/* Prints verbose output. */
void print_verbose(mpz_t n, mpz_t e) {
    gmp_printf("n (%zu bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
    gmp_printf("e (%zu bits) = %Zd\n", mpz_sizeinbase(n, 2), e);
}

int main(int argc, char **argv) {

    FILE *infile = NULL;
    FILE *outfile = NULL;
    FILE *pvfile = fopen("rsa.priv", "r");
    bool verbose = false;
    int opt;

    /* Parse command-line options. */
    while ((opt = getopt(argc, argv, "i:o:n:vh")) != -1) {
        switch (opt) {
        case 'i': infile = fopen(optarg, "r"); break;
        case 'o': outfile = fopen(optarg, "w"); break;
        case 'n': pvfile = fopen(optarg, "r"); break;
        case 'v': verbose = true; break;
        case 'h': usage(argv[0]); return 0;
        default: break;
        }
    }

    /* Check that the private key file is valid. */
    if (pvfile == NULL) {
        fprintf(stderr, "Invalid public key file.\n");
        return 1;
    }

    /* Set infile to stdin if none specified. */
    if (infile == NULL) {
        infile = stdin;
    }

    /* Set outfile to stdout if none specified. */
    if (outfile == NULL) {
        outfile = stdout;
    }

    /* Read the private key from the private key file. */
    mpz_t n, e;
    mpz_inits(n, e, NULL);

    rsa_read_priv(n, e, pvfile);

    /* If verbose is enabled, print verbose output. */
    if (verbose) {
        print_verbose(n, e);
    }

    /* Decrypt the file. */
    rsa_decrypt_file(infile, outfile, n, e);

    /* Close the public key file. */
    fclose(pvfile);

    /* Clear mpz_t variables. */
    mpz_clears(n, e, NULL);

    return 0;
}
