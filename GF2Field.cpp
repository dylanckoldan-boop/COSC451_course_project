#include "GF2Field.h"


/*
 * *** STUDENT-OWNED FILE ***
 * TODO (Week 4): implement each function below.
 */




// Position of the highest set bit, or -1 for x == 0. Doubles as the
// "degree of this polynomial" for every function below.
static int highest_bit(uint64_t x) {
    if (x == 0) {
        return -1;
    }
    int pos = 0;
    while (x >>= 1) {
        pos++;
    }
    return pos;
}

uint64_t gf_add(uint64_t a, uint64_t b) {
    return a ^ b;
}

uint64_t gf_mul(uint64_t a, uint64_t b) {
    uint64_t result = 0;
    while (b != 0) {
        if (b & 1) {
            result ^= a;
        }
        a <<= 1;
        b >>= 1;
    }
    return result;
}

uint64_t gf_reduce(uint64_t product, uint64_t irreducible_poly) {
    int poly_degree = highest_bit(irreducible_poly);
    int prod_degree = highest_bit(product);

    while (prod_degree >= poly_degree) {
        product ^= (irreducible_poly << (prod_degree - poly_degree));
        prod_degree = highest_bit(product);
    }

    return product;
}

bool gf_inverse(uint64_t a, uint64_t irreducible_poly, uint64_t& result) {
    if (a == 0) {
        return false;
    }

    // Extended Euclidean algorithm adapted to polynomials over GF(2):
    // same structure as mod_inverse's integer version, but "divide with
    // remainder" and "subtract" become polynomial long division and XOR.
    uint64_t old_r = a;
    uint64_t r = irreducible_poly;
    uint64_t old_s = 1;
    uint64_t s = 0;

    while (r != 0) {
        int r_degree = highest_bit(r);

        // Polynomial long division: old_r = q * r + rem (all over GF(2)).
        uint64_t q = 0;
        uint64_t rem = old_r;
        int rem_degree = highest_bit(rem);

        while (rem != 0 && rem_degree >= r_degree) {
            int shift = rem_degree - r_degree;
            q ^= (static_cast<uint64_t>(1) << shift);
            rem ^= (r << shift);
            rem_degree = highest_bit(rem);
        }

        old_r = r;
        r = rem;

        uint64_t temp_s = old_s ^ gf_mul(q, s);
        old_s = s;
        s = temp_s;
    }

    // old_r now holds gcd(a, irreducible_poly). Since irreducible_poly is
    // irreducible and a != 0, that gcd is always 1 -- but guard it anyway
    // rather than assuming the caller passed a genuinely irreducible poly.
    if (old_r != 1) {
        return false;
    }

    result = gf_reduce(old_s, irreducible_poly);
    return true;
}
