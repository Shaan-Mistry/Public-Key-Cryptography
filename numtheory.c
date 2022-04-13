#include "numtheory.h"
#include "randstate.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <gmp.h>

// Note: change to mpz when finished....

/* Performs fast modular exponentiation. */
void pow_mod(mpz_t out, mpz_t base, mpz_t exponent, mpz_t modulus) {

    mpz_t mod_exponent, exp, p;
    mpz_inits(mod_exponent, exp, p, NULL);

    mpz_set(exp, exponent);
    mpz_set(p, base);
    mpz_set_ui(out, 1);

    while (mpz_cmp_ui(exp, 0) > 0) { //exponent > 0

        mpz_mod_ui(mod_exponent, exp, 2); // exponent % 2

        if (mpz_cmp_ui(mod_exponent, 0) != 0) { // While exponent is odd.
            mpz_mul(out, out, p); //out = (out * p)
            mpz_mod(out, out, modulus); // out = out % modulus;
        }
        mpz_mul(p, p, p); // base = base * base
        mpz_mod(p, p, modulus); // base =  base % modulus

        mpz_div_ui(exp, exp, 2); // exponent /= 2;
    }

    mpz_clears(mod_exponent, exp, p, NULL);
}

bool is_prime(mpz_t n, uint64_t iters) {

    // If n is less than 2, return false.
    if (mpz_cmp_ui(n, 2) < 0) {
        return false;
    }
    // If n is 2 or 3, return true.
    if (mpz_cmp_ui(n, 2) == 0 || mpz_cmp_ui(n, 3) == 0) {
        return true;
    }

    // If n is even and n > 3 then n is composite.
    if (mpz_cmp_ui(n, 3) > 0 && mpz_even_p(n) != 0) {
        return false;
    }

    mpz_t r, s;
    mpz_inits(r, s, NULL); // s = 0
    mpz_sub_ui(r, n, 1); // r = n - 1

    while (mpz_even_p(r) != 0) { // while r is even.
        mpz_div_ui(r, r, 2); // r /= 2
        mpz_add_ui(s, s, 1); // s += 1
    }

    mpz_t a, m, y, j, two;
    mpz_inits(a, m, y, j, two, NULL);
    mpz_set_ui(two, 2);

    for (uint32_t i = 1; i <= iters; i += 1) {

        //a = ((rand() + 3) % (n - 3)) + 2;
        mpz_sub_ui(m, n, 3);
        mpz_urandomm(a, state, m);
        mpz_add_ui(a, a, 2);

        pow_mod(y, a, r, n);
        mpz_sub_ui(m, n, 1); // m = n - 1
        if (mpz_cmp_ui(y, 1) != 0 && mpz_cmp(y, m) != 0) {
            mpz_set_ui(j, 1);
            mpz_add_ui(s, s, 1); // s += 1
            while (mpz_cmp(j, s) <= 0 && mpz_cmp(y, m) != 0) { //j + 1 <= s && y != n - 1)
                pow_mod(y, y, two, n);
                if (mpz_cmp_ui(y, 1) == 0) { // y == 0
                    mpz_clears(r, s, a, m, y, j, two, NULL);
                    return false;
                }
                mpz_add_ui(j, j, 1); //j += 1;
            }
            if (mpz_cmp(y, m) != 0) { // y != n - 1
                mpz_clears(r, s, a, m, y, j, two, NULL);
                return false;
            }
        }
    }
    mpz_clears(r, s, a, m, y, j, two, NULL);
    return true;
}

void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {
    mpz_t rand_num, min, one;
    mpz_inits(rand_num, min, one, NULL);
    mpz_set_ui(one, 1);

    // min = 2^(bits). Code Inspried from Eugenes Lab Section (2/4/2022)
    mpz_mul_2exp(min, one, bits);
    while (1) {
        mpz_urandomb(rand_num, state, bits - 1); // gen random number from [0, 2^(n-1) - 1]
        mpz_add(rand_num, rand_num, min); // add min to random number.
        if (is_prime(rand_num, iters)) { // if random number is prime.
            mpz_set(p, rand_num);
            mpz_clears(rand_num, min, one, NULL);
            return;
        }
    }
}

void gcd(mpz_t d, mpz_t a, mpz_t b) {
    mpz_t mod_a, t, num_a, num_b;
    mpz_inits(mod_a, t, num_a, num_b, NULL);
    mpz_set(num_a, a);
    mpz_set(num_b, b);

    while (mpz_cmp_ui(num_b, 0) != 0) {
        mpz_set(t, num_b);
        mpz_mod(mod_a, num_a, num_b);
        mpz_set(num_b, mod_a);
        mpz_set(num_a, t);
    }
    mpz_set(d, num_a);
    mpz_clears(mod_a, t, num_a, num_b, NULL);
}

void mod_inverse(mpz_t i, mpz_t a, mpz_t n) {
    mpz_t r, r_prime, t, t_prime, q, temp, product;
    mpz_inits(r, r_prime, t, t_prime, q, temp, product, NULL);

    mpz_set(r, n); // r = n
    mpz_set(r_prime, a); // r' = a
    mpz_set_ui(t, 0); // t = 0
    mpz_set_ui(t_prime, 1); // t' = 1

    while (mpz_cmp_ui(r_prime, 0) != 0) { // r' != 0
        mpz_fdiv_q(q, r, r_prime); // q = floor r / r'

        mpz_set(temp, r); // Store r in temp.
        mpz_set(r, r_prime); // r = r'
        mpz_mul(product, q, r_prime); // q x r'
        mpz_sub(r_prime, temp, product); // r' = r - (q x r') -> (product)

        mpz_set(temp, t); // Store t in temp.
        mpz_set(t, t_prime); // t = t'
        mpz_mul(product, q, t_prime); // q x t'
        mpz_sub(t_prime, temp, product); // t' = t - (q x t') -> (product)
    }

    if (mpz_cmp_ui(r, 1) > 0) { // r > 1
        mpz_set(i, 0);
        return;
    }
    if (mpz_cmp_ui(t, 0) < 0) { // t < 0
        mpz_add(t, t, n);
    }
    mpz_set(i, t);
    mpz_clears(r, r_prime, t, t_prime, q, temp, product, NULL);
}
