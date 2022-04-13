#include "rsa.h"
#include "numtheory.h"
#include "randstate.h"

#include <stdlib.h>
#include <stdio.h>

/* Creates a new RSA public key. */
void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits, uint64_t iters) {

    uint64_t p_bits, q_bits;
    p_bits = random() % (3 * nbits / 4 + 1 - nbits / 4) + nbits / 4;
    q_bits = nbits - p_bits;

    make_prime(p, p_bits, iters);
    make_prime(q, q_bits, iters);
    mpz_mul(n, p, q);

    mpz_t lambda_n, p_minus_one, q_minus_one, product, pq_gcd;
    mpz_inits(lambda_n, p_minus_one, q_minus_one, product, pq_gcd, NULL);
    mpz_sub_ui(p_minus_one, p, 1);
    mpz_sub_ui(q_minus_one, q, 1);

    mpz_mul(product, p_minus_one, q_minus_one);
    gcd(pq_gcd, p_minus_one, q_minus_one);
    mpz_div(lambda_n, product, pq_gcd);
    // lambda(n) = ((p - 1) x (q - 1)) / gcd(p - 1, q - 1)
    mpz_clears(p_minus_one, q_minus_one, product, NULL);

    mpz_t rand_e;
    mpz_init(rand_e);
    while (1) {
        mpz_urandomb(rand_e, state, nbits);
        gcd(pq_gcd, rand_e, lambda_n);
        if (mpz_cmp_ui(pq_gcd, 1) == 0) {
            mpz_set(e, rand_e);
            mpz_clears(rand_e, pq_gcd, lambda_n, NULL);
            return;
        }
    }
}

/* Writes public RSA key to pbfile. */
void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fprintf(pbfile, "%Zx\n", n);
    gmp_fprintf(pbfile, "%Zx\n", e);
    gmp_fprintf(pbfile, "%Zx\n", s);
    fprintf(pbfile, "%s\n", username);
}

/* Reads public RSA key from pbfile */
void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fscanf(pbfile, "%Zx\n", n);
    gmp_fscanf(pbfile, "%Zx\n", e);
    gmp_fscanf(pbfile, "%Zx\n", s);
    fscanf(pbfile, "%sx\n", username);
}

/* Creates a new RSA private key. */
void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q) {

    mpz_t lambda_n, p_minus_one, q_minus_one, product, pq_gcd;
    mpz_inits(lambda_n, p_minus_one, q_minus_one, product, pq_gcd, NULL);
    mpz_sub_ui(p_minus_one, p, 1);
    mpz_sub_ui(q_minus_one, q, 1);

    mpz_mul(product, p_minus_one, q_minus_one);
    gcd(pq_gcd, p_minus_one, q_minus_one);
    mpz_div(lambda_n, product, pq_gcd);

    mod_inverse(d, e, lambda_n);
    mpz_clears(lambda_n, p_minus_one, q_minus_one, product, pq_gcd, NULL);
}

/* Writes private RSA key to pvfile. */
void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fprintf(pvfile, "%Zx\n", n);
    gmp_fprintf(pvfile, "%Zx\n", d);
}

/* Reads private RSA key from pvfile. */
void rsa_read_priv(mpz_t n, mpz_t e, FILE *pvfile) {
    gmp_fscanf(pvfile, "%Zx\n", n);
    gmp_fscanf(pvfile, "%Zx\n", e);
}

/* Performs RSA encryption. */
void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) {
    pow_mod(c, m, e, n);
}

/* Encrypts the contents of infile and writes the encryped conent to outfile. */
void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e) {

    mpz_t c, m;
    mpz_inits(c, m, NULL);

    size_t k = (mpz_sizeinbase(n, 2) - 1) / 8; // Calculate block size.

    uint8_t *block = (uint8_t *) calloc(k, sizeof(uint8_t));
    block[0] = 0xFF; // Prepend a byte to the front of the block.

    while (feof(infile) == 0) {
        size_t j = fread(block + 1, sizeof(uint8_t), k - 1, infile);
        if (j > 0) {
            mpz_import(m, j + 1, 1, sizeof(uint8_t), 1, 0, block);
            rsa_encrypt(c, m, e, n);
            gmp_fprintf(outfile, "%Zx\n", c);
        }
    }
    mpz_clears(c, m, NULL);
    free(block);
}

/* Performs RSA decryption. */
void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {
    pow_mod(m, c, d, n);
}

/* Decrypt the contents of infile and write the contents in outfile. */
void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d) {
    mpz_t c;
    mpz_init(c);

    size_t k = (mpz_sizeinbase(n, 2) - 1) / 8;
    uint8_t *block = (uint8_t *) calloc(k, sizeof(uint8_t));

    size_t j;
    while (gmp_fscanf(infile, "%Zx\n", c) != EOF) {

        rsa_decrypt(c, c, d, n);
        mpz_export(block, &j, sizeof(uint8_t), 1, 1, 0, c);

        if (j > 1) {
            fwrite(block + 1, sizeof(uint8_t), j, outfile);
        }
    }
    mpz_clear(c);
    free(block);
}

/* Performs RSA signing, producing a signiture. */
void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) {
    pow_mod(s, m, d, n);
}

/* Performs RSA verification on the inputted signiture. */
bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n) {
    mpz_t t;
    mpz_init(t);
    pow_mod(t, s, e, n);
    if (mpz_cmp(t, m) == 0) {
        mpz_clear(t);
        return true;
    }
    mpz_clear(t);
    return false;
}
