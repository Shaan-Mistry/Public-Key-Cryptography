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
        "   Encrypts data using RSA encryption.\n"
        "   Encrypted data is decrypted be the decrypt program.\n"
        "\n"
        "USAGE\n"
        "   %s [-hv] [-i infile] [-o outfile] -n pubkey -d privkey\n"
        "\n"
        "OPTIONS\n"
        "   -h              Display program help and usage.\n"
        "   -v              Display verbose program output.\n"
        "   -i infile       Input file of data to encrypt (default: stdin).\n"
        "   -o outfile      Output file for encrypted data (default: stdout).\n"
        "   -n pbfile       Public key file (default: rsa.pub).\n",
        exec);
}

/* Prints verbose output. */
void print_verbose(char *username, mpz_t s, mpz_t n, mpz_t e) {
    printf("user = %s\n", username);
    gmp_printf("s (%zu bits) = %Zd\n", mpz_sizeinbase(s, 2), s);
    gmp_printf("n (%zu bits) = %Zd\n", mpz_sizeinbase(n, 2), n);
    gmp_printf("e (%zu bits) = %Zd\n", mpz_sizeinbase(n, 2), e);
}

int main(int argc, char **argv) {

    FILE *infile = NULL;
    FILE *outfile = NULL;
    FILE *pbfile = fopen("rsa.pub", "r");
    bool verbose = false;
    int opt;

    /* Parse command-line options. */
    while ((opt = getopt(argc, argv, "i:o:n:vh")) != -1) {
        switch (opt) {
        case 'i': infile = fopen(optarg, "r"); break;
        case 'o': outfile = fopen(optarg, "w"); break;
        case 'n': pbfile = fopen(optarg, "r"); break;
        case 'v': verbose = true; break;
        case 'h': usage(argv[0]); return 0;
        default: break;
        }
    }

    /* Check that the public key file is valid. */
    if (pbfile == NULL) {
        fprintf(stderr, "Error: Invalid public key file.\n");
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

    /* Read the public key from the public key file. */
    mpz_t n, e, s;
    mpz_inits(n, e, s, NULL);
    char username_str[256] = { 0 }; // Code Inspired from eth0#6012 on discord.

    rsa_read_pub(n, e, s, username_str, pbfile);

    /* If verbose is enabled, print verbose output. */
    if (verbose) {
        print_verbose(username_str, s, n, e);
    }

    /* Convert username to an mpz_t. */
    mpz_t username;
    mpz_init(username);
    mpz_set_str(username, username_str, 62);

    /* Verify the signature with username as target. */
    if (!rsa_verify(username, s, e, n)) {
        fprintf(stderr, "Error: Unverified signature\n");
        return 1;
    }

    /* Encrypt the file. */
    rsa_encrypt_file(infile, outfile, n, e);

    /* Close the opened files. */
    fclose(pbfile);
    fclose(infile);
    fclose(outfile);

    /* Clear mpz_t variables. */
    mpz_clears(username, n, e, s, NULL);

    return 0;
}
