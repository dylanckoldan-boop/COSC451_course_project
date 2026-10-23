#pragma once
#include <string>
#include <cryptopp/integer.h>

/*
 * SSLUtil
 * -------
 * Small helpers for the Week 6 SSL simulation. Everything here is either
 * a thin wrapper around a library primitive (SHA-256, random bytes, the
 * system clock) or fixed public data (the Diffie-Hellman group) -- none
 * of it is handshake or certificate logic, which lives in the classes
 * marked .
 */
namespace SSLUtil {

// SHA-256 digest of `data`, as 32 raw bytes.
std::string sha256(const std::string& data);

// Cryptographically secure random bytes (for client/server randoms,
// pre-master secrets, DH private values, certificate serial numbers).
std::string randomBytes(size_t count);

// Today's date as "YYYY-MM-DD". ISO dates in this format compare
// correctly as plain strings ("2026-10-02" < "2027-01-15"), so an
// expiry check can be a simple string comparison.
std::string todayISODate();
// The date `years` years from today, same format -- for issuing
// certificates that are valid for a realistic period.
std::string dateYearsFromToday(int years);

// Puts back leading 0x00 bytes that textbook RSA (and any big-integer
// round trip) drops -- the same fix as HybridCrypto::restoreSessionKeyLength,
// but for any target length. Returns false if `bytes` is already LONGER
// than `length` (meaning the value can't be what was expected).
bool leftPad(std::string& bytes, size_t length);

// CryptoPP::Integer <-> decimal string / raw bytes, for putting big
// numbers (DH public values, signatures) into handshake messages.
std::string toDecimal(const CryptoPP::Integer& value);
std::string toBytes(const CryptoPP::Integer& value);
CryptoPP::Integer fromBytes(const std::string& bytes);

// Diffie-Hellman Group 14 from RFC 3526: a standardized 2048-bit safe
// prime p with generator g = 2. Real TLS/IKE implementations use
// published groups like this instead of generating a fresh prime per
// connection (which would take seconds). Like DESTables.h, this is
// fixed public data -- every implementation uses the same numbers.
// (Verified against the RFC's defining formula, and that p and (p-1)/2
// are both prime.)
CryptoPP::Integer dhGroup14Prime();
CryptoPP::Integer dhGroup14Generator();

} // namespace SSLUtil
