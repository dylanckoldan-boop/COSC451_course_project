#include "PayloadSimDemo.h"
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>

namespace {

// A fixed, obvious marker string. Harmless in itself, but it plays the
// role a real malware "signature" would: a unique byte sequence an
// antivirus scanner could match on. We print it and write it into the
// self-copy so the report can point to it concretely.
const char* const BENIGN_SIGNATURE = "EDU-BENIGN-SIM-v1-{harmless-demo-marker}";

// The single folder the self-copy is allowed to write into. Keeping it to
// one named, user-visible subfolder is part of staying harmless: no
// scattering copies around the filesystem.
const char* const SANDBOX_DIR = "payload_sim_sandbox";

// --- The "payload" -----------------------------------------------------
// Fires only when today is on or after the trigger date. It does nothing
// but print. That's the whole payload -- the educational content is the
// CONDITIONAL TRIGGER itself (malware often lies dormant until a date,
// a file appears, etc.), not any effect.
void maybeFirePayload(const std::string& triggerDate, const std::string& today) {
    std::cout << "\n  [payload check] trigger date = " << triggerDate
              << ", today = " << today << "\n";
    if (today >= triggerDate) { // ISO dates compare correctly as strings
        std::cout << "  [payload FIRED] Condition met. Benign banner:\n"
                  << "      >> \"" << BENIGN_SIGNATURE << "\" says hello. <<\n"
                  << "  (A real time-bomb would act here; this one only prints.)\n";
    } else {
        std::cout << "  [payload dormant] Trigger date not reached; nothing happens.\n";
    }
}

// --- The "self-copy" ---------------------------------------------------
// Writes ONE labelled text file into SANDBOX_DIR describing itself, and
// refuses if that file already exists -- so running the demo repeatedly
// never produces more than a single copy. This models "replication" at
// its most harmless: a self-describing file placed once, in one spot.
//
// We copy a short self-description rather than a runnable program on
// purpose: an inert .txt can't execute, so even the replicated artifact
// is harmless.
void simulateSelfCopy(const std::string& today) {
    std::string path = std::string(SANDBOX_DIR) + "/replica_marker.txt";

    std::ifstream exists(path);
    if (exists.good()) {
        std::cout << "\n  [self-copy] A replica already exists at " << path << "\n"
                  << "  Refusing to copy again (bounded replication -- no runaway spread).\n";
        return;
    }

    std::ofstream out(path);
    if (!out.is_open()) {
        std::cout << "\n  [self-copy] Could not create " << SANDBOX_DIR
                  << "/. Create that folder next to the program and retry.\n"
                  << "  (Nothing was written. The simulation stays contained.)\n";
        return;
    }
    out << "Benign payload simulation -- replica marker\n"
        << "Signature: " << BENIGN_SIGNATURE << "\n"
        << "Written on: " << today << "\n"
        << "This inert text file is the ONLY thing this demo replicates.\n"
        << "It does not run, spread, or alter any other file.\n";
    out.close();

    std::cout << "\n  [self-copy] Wrote a single inert replica to " << path << "\n"
              << "  That's the entire replication step -- one labelled file, one folder.\n";
}

std::string todayISO() {
    std::time_t now = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &now);
#else
    localtime_r(&now, &tm);
#endif
    char buf[11];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tm);
    return std::string(buf);
}

} // namespace

namespace PayloadSimDemo {

void run() {
    std::cout << "\n=== Part 3: Virus Payload Simulation (benign) ===\n";
    std::cout << "This is a HARMLESS illustration of two malware-associated behaviors:\n"
              << "a date-triggered payload and a bounded self-copy. It infects nothing,\n"
              << "spreads nowhere, and its 'payload' only prints text.\n";

    std::string today = todayISO();

    // Show the dormant case and the fired case, so both branches of the
    // trigger are visible in one run.
    std::cout << "\n[A] Payload with a FUTURE trigger date (stays dormant):\n";
    maybeFirePayload("2099-01-01", today);

    std::cout << "\n[B] Payload with a PAST trigger date (fires -- prints only):\n";
    maybeFirePayload("2000-01-01", today);

    std::cout << "\n[C] Bounded self-copy into ./" << SANDBOX_DIR << "/ :\n";
    simulateSelfCopy(today);

    std::cout << "\nHow antivirus would detect something like this:\n"
              << "  - Signature matching: the fixed marker string\n"
              << "    \"" << BENIGN_SIGNATURE << "\"\n"
              << "    is a unique byte pattern a scanner can hash and blocklist --\n"
              << "    this is how classic signature-based AV works.\n"
              << "  - Heuristics / behavior monitoring: a program that writes copies\n"
              << "    of itself, or checks the date and then changes its behavior,\n"
              << "    matches suspicious-behavior patterns even with no known signature.\n"
              << "  - Sandboxing: AV can run an unknown program in an isolated\n"
              << "    environment and watch for replication or a time-triggered action\n"
              << "    before letting it run for real.\n"
              << "  Defenses: keep AV definitions current, apply least privilege so a\n"
              << "  program can't write where it shouldn't, and use allow-listing for\n"
              << "  what's permitted to execute.\n";
}

} // namespace PayloadSimDemo
