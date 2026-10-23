#include "BufferOverflowDemo.h"
#include <iostream>
#include <string>
#include <cstring>

namespace {

// Two fields side by side. In the classic teaching example, `secret`
// stands in for something an overflow of `username` could clobber -- a
// flag, a saved return address, an adjacent variable. Laying them out in
// one struct makes "adjacent in memory" concrete and the corruption
// visible, without depending on the exact stack layout a real overflow
// would exploit.
struct LoginRecord {
    char username[8];      // the small, fixed-size buffer
    char accessLevel[8];   // the neighbor an overflow spills into
};

void printState(const LoginRecord& rec, const char* label) {
    // Print each field defensively: stop at 8 chars so a non-terminated
    // buffer can't run away on us while we're displaying it.
    auto safeShow = [](const char* field) {
        std::string out;
        for (int i = 0; i < 8 && field[i] != '\0'; i++) out += field[i];
        return out.empty() ? "(empty)" : out;
    };
    std::cout << "    " << label << " username=\"" << safeShow(rec.username)
              << "\", accessLevel=\"" << safeShow(rec.accessLevel) << "\"\n";
}

// A MANUAL, BOUNDED copy that deliberately allows writing up to `limit`
// bytes into the destination -- which may be MORE than the destination
// field holds. This is how we SIMULATE an overflow: we reproduce the
// effect (spilling into the next field) using an explicit loop we fully
// control, instead of a real strcpy that could run arbitrarily far into
// memory and crash. `limit` caps the damage at the struct's own size so
// the demonstration stays safe and repeatable.
void simulateUnsafeCopy(LoginRecord& rec, const std::string& input, size_t limit) {
    // Treat the struct as a flat run of bytes starting at `username`, and
    // copy up to `limit` bytes. When input is longer than username's 8
    // bytes, the extra bytes land in accessLevel -- exactly the overflow
    // effect, but bounded to this struct and nothing beyond it.
    char* base = rec.username;
    size_t n = input.size();
    if (n > limit) n = limit;
    for (size_t i = 0; i < n; i++) {
        base[i] = input[i];
    }
}

// The safe version: copy no more than the destination can hold, and
// always leave room for a terminator. This is the fix -- the copy simply
// cannot reach the neighboring field.
void safeCopy(char* dest, size_t destSize, const std::string& input) {
    size_t n = input.size();
    if (n > destSize - 1) n = destSize - 1; // reserve 1 byte for '\0'
    for (size_t i = 0; i < n; i++) dest[i] = input[i];
    dest[n] = '\0';
}

} // namespace

namespace BufferOverflowDemo {

void run() {
    std::cout << "\n=== Part 2: Buffer Overflow (simulated) ===\n";
    std::cout << "A LoginRecord places an 8-byte username buffer directly before\n"
              << "an 8-byte accessLevel field. Copying an over-long username spills\n"
              << "past the buffer and overwrites the neighbor.\n";

    // ---- Baseline: a normal, in-bounds write --------------------------
    LoginRecord rec;
    std::memset(&rec, 0, sizeof(rec));
    safeCopy(rec.accessLevel, sizeof(rec.accessLevel), "user"); // start as a normal user
    safeCopy(rec.username, sizeof(rec.username), "bob");
    std::cout << "\n[A] Normal login, short username \"bob\":\n";
    printState(rec, "after:");
    std::cout << "    Fits in 8 bytes; accessLevel is untouched (still \"user\").\n";

    // ---- The overflow (simulated, bounded) ----------------------------
    // Reset, then copy a 12-char username into the 8-byte field. The 4
    // extra bytes run into accessLevel. We cap the copy at the struct size
    // so nothing beyond this struct is ever written.
    std::memset(&rec, 0, sizeof(rec));
    safeCopy(rec.accessLevel, sizeof(rec.accessLevel), "user");
    std::string oversized = "AAAAAAAAadmin"; // 8 'A's fill username, "admin" spills over
    std::cout << "\n[B] Oversized username \"" << oversized << "\" ("
              << oversized.size() << " bytes) into an 8-byte buffer:\n";
    simulateUnsafeCopy(rec, oversized, sizeof(rec)); // bounded to the struct
    printState(rec, "after:");
    std::cout << "    The bytes past position 8 overwrote accessLevel -- it now\n"
              << "    reads \"admin\" instead of \"user\". In a real program this is how\n"
              << "    an overflow silently changes an adjacent variable; if the\n"
              << "    neighbor were a saved return address, controlling those bytes\n"
              << "    is how an attacker redirects execution.\n";

    // ---- The fix ------------------------------------------------------
    std::memset(&rec, 0, sizeof(rec));
    safeCopy(rec.accessLevel, sizeof(rec.accessLevel), "user");
    std::cout << "\n[C] The SAME oversized input through a bounds-checked copy:\n";
    safeCopy(rec.username, sizeof(rec.username), oversized);
    printState(rec, "after:");
    std::cout << "    The safe copy wrote at most 7 bytes + a terminator, so the\n"
              << "    username is truncated and accessLevel stays \"user\". The\n"
              << "    overflow is impossible.\n";

    std::cout << "\nDefenses against buffer overflows:\n"
              << "  - Bounds checking: never copy more than the destination holds\n"
              << "    (use std::string / std::vector, or strncpy/snprintf with sizes;\n"
              << "    avoid strcpy, gets, sprintf).\n"
              << "  - Stack canaries: a guard value placed before the return address;\n"
              << "    the function checks it's intact before returning. Enabled by the\n"
              << "    compiler flag -fstack-protector (/GS on MSVC).\n"
              << "  - Non-executable stack (DEP/NX) + ASLR: make overwritten memory\n"
              << "    non-runnable and randomize addresses so overflows are far harder\n"
              << "    to turn into working exploits.\n"
              << "  - Compiler/runtime hardening: _FORTIFY_SOURCE, AddressSanitizer\n"
              << "    during testing to catch overflows before shipping.\n";
}

} // namespace BufferOverflowDemo
