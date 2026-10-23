#pragma once

/*
 * SSLScenarios
 * ------------
 * Provided test suite and sample-output generator for the Week 6
 * simulation. Builds a small world -- a trusted CA ("issuerCA"), an
 * untrusted one ("EvilCA"), an honest server for www.securechat.com, and
 * an attacker -- then runs honest handshakes and attacks against your
 * implementation.
 *
 * Each attack states the EXACT pattern of check results a correct
 * implementation should produce (e.g. "issuer trusted, signature INVALID,
 * not expired, hostname matches"), so a validator that rejects for the
 * wrong reason -- or rejects everything -- fails the test instead of
 * passing by accident.
 *
 * Called from Menu's "SSL Handshake Simulation" option.
 */
namespace SSLScenarios {

// One honest handshake with a full step-by-step log.
void runHonestHandshake(bool useDHE);

// All attack scenarios. verbose = full handshake log for each (good for
// sample output); otherwise one result line per attack.
void runAttackScenarios(bool verbose);

// Everything: honest RSA + DHE handshakes, all attacks, a 1,000-certificate
// signature reliability check, and an RSA vs DHE timing comparison, with a
// PASS/FAIL summary.
void runFullSuite();

} // namespace SSLScenarios
