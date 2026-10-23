#include "NumberTheory.h"


/*
 * *** STUDENT-OWNED FILE ***
 * TODO (Week 4): implement each function below.
 */






uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

bool mod_inverse(uint64_t a, uint64_t n, uint64_t& result) {
    if (n == 0) {
        return false;
    }

    // Extended Euclidean algorithm, done in signed 64-bit arithmetic since
    // the Bezout coefficients can go negative along the way.
    int64_t old_r = static_cast<int64_t>(a % n);
    int64_t r = static_cast<int64_t>(n);
    int64_t old_s = 1;
    int64_t s = 0;

    while (r != 0) {
        int64_t quotient = old_r / r;

        int64_t temp_r = old_r - quotient * r;
        old_r = r;
        r = temp_r;

        int64_t temp_s = old_s - quotient * s;
        old_s = s;
        s = temp_s;
    }

    // old_r now holds gcd(a, n). An inverse exists iff that gcd is 1.
    if (old_r != 1) {
        return false;
    }

    int64_t inv = old_s % static_cast<int64_t>(n);
    if (inv < 0) {
        inv += static_cast<int64_t>(n);
    }

    result = static_cast<uint64_t>(inv);
    return true;
}

// (a * b) % mod without ever forming a*b directly -- a*b can overflow
// uint64_t even when a, b, and mod all fit in it, and __uint128_t isn't
// portable (MSVC doesn't have it). This computes the product via
// "russian peasant" binary addition instead, staying under mod at every
// step, so it works with plain uint64_t on any compiler.
static uint64_t mulmod(uint64_t a, uint64_t b, uint64_t mod) {
    uint64_t result = 0;
    a %= mod;

    while (b > 0) {
        if (b & 1) {
            result = (result + a) % mod;
        }
        a = (a + a) % mod;
        b >>= 1;
    }

    return result;
}

uint64_t mod_exp(uint64_t base, uint64_t exponent, uint64_t mod) {
    if (mod == 1) {
        return 0;
    }

    uint64_t result = 1;
    base %= mod;

    while (exponent > 0) {
        if (exponent & 1) {
            result = mulmod(result, base, mod);
        }
        exponent >>= 1;
        base = mulmod(base, base, mod);
    }

    return result;
}
