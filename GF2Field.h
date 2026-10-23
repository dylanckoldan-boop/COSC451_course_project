#pragma once
#include <cstdint>

/*
 * GF2Field
 * --------
 ** *** STUDENT-OWNED FILE -- Week 4 deliverable. ***
 * Binary field (GF(2^n)) arithmetic -- the building blocks AES's S-box
 * construction and MixColumns rely on, and that binary-field elliptic
 * curve systems will reuse in a later week.
 * 
 * Binary polynomials are represented as plain integers: bit i of the
 * integer is the coefficient of x^i. E.g. 0b1011 represents x^3 + x + 1.
 *
 * gf_mul() deliberately does NOT reduce its result -- the assignment
 * lists gf_mul and gf_reduce as two separate functions on purpose, so a
 * caller wanting a fully reduced product calls both in sequence:
 * gf_reduce(gf_mul(a, b), irreducible_poly). Keeping them separate means
 * gf_inverse (or any future caller) can reuse raw multiplication without
 * a fixed field size baked into gf_mul itself.
 */

// XOR -- addition and subtraction are the same operation in GF(2^n).
uint64_t gf_add(uint64_t a, uint64_t b);

// Carryless polynomial multiplication, UNREDUCED. For n-bit inputs the
// result can be up to (2n - 1) bits wide -- callers reduce separately.
uint64_t gf_mul(uint64_t a, uint64_t b);

// Reduces a wide product modulo the given irreducible polynomial,
// bringing the result back down to fit within the field's bit width.
uint64_t gf_reduce(uint64_t product, uint64_t irreducible_poly);

// Multiplicative inverse of a within GF(2^n) defined by irreducible_poly,
// via the Extended Euclidean Algorithm adapted to polynomials over
// GF(2). Returns true and sets result if an inverse exists; returns
// false (e.g. a == 0) otherwise -- same "explicit failure, not a
// sentinel value" pattern as mod_inverse.
bool gf_inverse(uint64_t a, uint64_t irreducible_poly, uint64_t& result);
