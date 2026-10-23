#pragma once
#include <cstdint>

/*
 * NumberTheory
 * ------------
 ** *** STUDENT-OWNED FILE -- Week 4 deliverable. ***
 * Foundational modular-arithmetic building blocks. mod_exp in particular
 * is what RSA-style encrypt/decrypt calls directly in a later week, and
 * mod_inverse is what RSA key generation needs.
 * 
 * uint64_t throughout, not int/long -- gives headroom well past 32 bits
 * for when RSA-sized numbers show up later, without needing a full
 * arbitrary-precision bignum type for this week's scope.
 */

// Greatest common divisor via the Euclidean algorithm.
uint64_t gcd(uint64_t a, uint64_t b);

// Modular inverse of a mod n: finds x such that (a * x) % n == 1.
// Returns true and sets result if an inverse exists (iff gcd(a, n) == 1).
// Returns false, leaving result untouched, otherwise -- this is the
// "no inverse exists" case Part 2 explicitly asks you to test, so the
// return value needs to make that case checkable rather than ambiguous.
bool mod_inverse(uint64_t a, uint64_t n, uint64_t& result);

// Fast modular exponentiation: (base ^ exponent) % mod, via
// square-and-multiply rather than naive repeated multiplication.
uint64_t mod_exp(uint64_t base, uint64_t exponent, uint64_t mod);
