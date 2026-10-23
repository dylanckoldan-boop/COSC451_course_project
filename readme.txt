///////////////////////////////////////////////////////////////////////////////////////////////////
//This is a readme file for instructions on viewing the benchmarking test for the numbertheory.cpp
//and the gf2field.cpp
//
//The program should be set to only include the UtilityTests.cpp for this weeks upload.
//However, in the event that there is a compile error due to multiple instances of a main() 
//go into the repository and remove the main.cpp from the repository to run the tests
//contained in numbertheory.cpp and gf2field.cpp.
//
//If you wish to run the main program for the enciphering sandbox replace the UtilityTests.cpp with
//the main.cpp.
//
//There are 3 functions total, the gf2 field operations
//
//
//the following comment lines are within the .h files that describe the functions and their purpose.
//
//gf2field.h
//comment line 4:
/* Binary field (GF(2^n)) arithmetic -- the building blocks AES's S-box
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
/* a fixed field size baked into gf_mul itself.
//
//
//numbertheory.h
//comment line 17:
// Greatest common divisor via the Euclidean algorithm.
uint64_t gcd(uint64_t a, uint64_t b);
//
// Modular inverse of a mod n: finds x such that (a * x) % n == 1.
// Returns true and sets result if an inverse exists (iff gcd(a, n) == 1).
// Returns false, leaving result untouched, otherwise -- this is the
// "no inverse exists" case Part 2 explicitly asks you to test, so the
// return value needs to make that case checkable rather than ambiguous.
bool mod_inverse(uint64_t a, uint64_t n, uint64_t& result);
//
// Fast modular exponentiation: (base ^ exponent) % mod, via
// square-and-multiply rather than naive repeated multiplication.
uint64_t mod_exp(uint64_t base, uint64_t exponent, uint64_t mod);
//
//
///////////////////////////////////////////////////////////////////////////////////////////////////