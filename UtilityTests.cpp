#include "NumberTheory.h"
#include "GF2Field.h"
#include <iostream>
#include <iomanip>

/*
 * UtilityTests.cpp
 * ----------------
 * Labeled test cases for Part 2. Expected values below are independently
 * verifiable (hand-computable for the number theory cases; the GF(2^8)
 * case is the literal worked example from FIPS-197 section 4.2, the AES
 * spec itself) -- so a mismatch tells you your implementation is wrong,
 * not that the test's expectation might be wrong.
 *
 * Each test prints PASS/FAIL rather than using assert(), so a single
 * failure doesn't stop the rest of the suite from running and reporting.
 */

static int passCount = 0;
static int failCount = 0;

static void checkEqual(const std::string& label, uint64_t actual, uint64_t expected) {
    if (actual == expected) {
        std::cout << "[PASS] " << label << "\n";
        passCount++;
    } else {
        std::cout << "[FAIL] " << label
                   << " -- expected " << expected << ", got " << actual << "\n";
        failCount++;
    }
}

static void checkTrue(const std::string& label, bool actual, bool expected) {
    if (actual == expected) {
        std::cout << "[PASS] " << label << "\n";
        passCount++;
    } else {
        std::cout << "[FAIL] " << label
                   << " -- expected " << (expected ? "true" : "false")
                   << ", got " << (actual ? "true" : "false") << "\n";
        failCount++;
    }
}

int main() {
    std::cout << "=== gcd ===\n";
    checkEqual("gcd(48, 18) == 6",  gcd(48, 18), 6);
    checkEqual("gcd(17, 5) == 1 (coprime)", gcd(17, 5), 1);
    checkEqual("gcd(0, 5) == 5 (edge case: one operand zero)", gcd(0, 5), 5);
    checkEqual("gcd(0, 0) == 0 (edge case: both zero -- decide/document this in your README)", gcd(0, 0), 0);

    std::cout << "\n=== mod_inverse ===\n";
    {
        uint64_t result = 0;
        bool ok = mod_inverse(3, 11, result);
        checkTrue("mod_inverse(3, 11) exists", ok, true);
        if (ok) checkEqual("mod_inverse(3, 11) == 4 (3*4=12 = 1 mod 11)", result, 4);
    }
    {
        uint64_t result = 0;
        bool ok = mod_inverse(4, 8, result);
        checkTrue("mod_inverse(4, 8) does NOT exist (gcd(4,8)=4 != 1)", ok, false);
    }

    std::cout << "\n=== mod_exp ===\n";
    checkEqual("mod_exp(3, 13, 7) == 3", mod_exp(3, 13, 7), 3);
    checkEqual("mod_exp(5, 0, 13) == 1 (edge case: exponent 0)", mod_exp(5, 0, 13), 1);

    std::cout << "\n=== gf_add ===\n";
    checkEqual("gf_add(0x57, 0x83) == 0xD4 (FIPS-197 example)", gf_add(0x57, 0x83), 0xD4);

    std::cout << "\n=== gf_mul + gf_reduce (AES's GF(2^8), poly 0x11B) ===\n";
    checkEqual("gf_reduce(gf_mul(0x57, 0x83), 0x11B) == 0xC1 (FIPS-197 4.2 worked example)",
               gf_reduce(gf_mul(0x57, 0x83), 0x11B), 0xC1);

    std::cout << "\n=== gf_inverse ===\n";
    {
        uint64_t result = 0;
        bool ok = gf_inverse(0, 0x11B, result);
        checkTrue("gf_inverse(0, ...) does NOT exist (0 has no multiplicative inverse)", ok, false);
    }

    std::cout << "\n" << passCount << " passed, " << failCount << " failed.\n";
    return failCount == 0 ? 0 : 1;
}






//cited: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf <-- links to the the AES nist description of the example referenced as 4.2.  This example is in a withdrawn publication superseeded by NIST FIPS 197-upd1.