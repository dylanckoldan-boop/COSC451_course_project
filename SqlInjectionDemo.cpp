#include "SqlInjectionDemo.h"
#include <iostream>
#include <string>
#include <vector>
#include <cctype>  // std::tolower

namespace {

// ---- A stand-in for a real database table ------------------------------
// One row = one user. In a real system this lives in a SQL database; here
// it's just an in-memory list so the demo is self-contained.
struct UserRow {
    std::string username;
    std::string password;
};

std::vector<UserRow> usersTable() {
    return {
        {"alice", "wonderland"},
        {"bob",   "builder123"},
        {"admin", "s3cr3t_admin_pw"},
    };
}

// ---- A deliberately naive "SQL engine" ---------------------------------
// It only understands ONE query shape, the one our login builds:
//
//   SELECT * FROM users WHERE username='...' AND password='...'
//
// It evaluates the WHERE clause the way a real SQL parser would -- and
// crucially, it honors the two pieces of SQL syntax the classic attack
// abuses: the OR operator and the -- comment marker. That's what lets the
// demo show a REAL logic bypass rather than a hand-waved one.
//
// Returns the number of rows the query would match. A login treats
// "1 or more rows matched" as success.
//
// This is NOT a real SQL parser and isn't meant to be reused -- it exists
// only to make the injection's effect concrete and visible.
int runNaiveQuery(const std::string& whereClause, const std::vector<UserRow>& rows) {
    // Strip anything after a "--" comment marker, exactly as SQL would:
    // everything past it is ignored, including the AND password=... check.
    std::string clause = whereClause;
    size_t comment = clause.find("--");
    if (comment != std::string::npos) {
        clause = clause.substr(0, comment);
    }

    // Detect a standalone "OR '1'='1'" / "OR 1=1" style tautology. A real
    // engine evaluates this as "always true", so the WHERE matches every
    // row regardless of the username/password tests around it.
    auto containsTautology = [](const std::string& c) {
        // Normalize: lowercase, remove spaces and single quotes, so
        // variants like  OR '1'='1'  and  or 1=1  both reduce to "or1=1".
        std::string norm;
        for (char ch : c) {
            if (ch == ' ' || ch == '\'') continue;
            norm += static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        return norm.find("or1=1") != std::string::npos;
    };

    if (containsTautology(clause)) {
        return static_cast<int>(rows.size()); // tautology -> every row matches
    }

    // Otherwise, parse the honest shape:  username='X' AND password='Y'
    // (good enough for the demo's legitimate-login path).
    auto extractQuoted = [](const std::string& c, const std::string& field) -> std::string {
        size_t f = c.find(field + "=");
        if (f == std::string::npos) return std::string("\x01no-match"); // sentinel
        size_t open = c.find('\'', f);
        if (open == std::string::npos) return std::string("\x01no-match");
        size_t close = c.find('\'', open + 1);
        if (close == std::string::npos) return std::string("\x01no-match");
        return c.substr(open + 1, close - open - 1);
    };

    std::string wantUser = extractQuoted(clause, "username");
    std::string wantPass = extractQuoted(clause, "password");

    int matches = 0;
    for (const UserRow& row : rows) {
        bool userOk = (row.username == wantUser);
        // If the comment marker ate the password test, there's no password
        // constraint left -- username alone decides the match.
        bool passOk = (wantPass == std::string("\x01no-match")) || (row.password == wantPass);
        if (userOk && passOk) matches++;
    }
    return matches;
}

// ---- The VULNERABLE login ----------------------------------------------
// Builds the query by pasting user input straight into the SQL string.
// This is the bug: the input can contain SQL syntax, and the engine can't
// tell the attacker's syntax apart from the query's own.
bool vulnerableLogin(const std::string& username, const std::string& password, bool showQuery) {
    std::string query =
        "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
    if (showQuery) {
        std::cout << "    Built query: " << query << "\n";
    }
    // The engine sees only the finished string -- same as a real DB driver
    // that's handed a concatenated query.
    std::string whereClause = query.substr(query.find("WHERE ") + 6);
    return runNaiveQuery(whereClause, usersTable()) > 0;
}

// ---- The SAFE login -----------------------------------------------------
// Two independent defenses, either of which alone stops the attack:
//
//  1. Parameterized query: the username/password are passed as DATA to
//     placeholders, never spliced into the query text. The engine compares
//     them as literal strings, so  ' OR 1=1--  is just a (wrong) password,
//     not executable syntax. This is the real fix.
//
//  2. Input validation: reject inputs containing SQL metacharacters before
//     they get anywhere. Defense-in-depth, not a substitute for #1 --
//     blocklists miss things, so parameterization stays the primary guard.
bool inputLooksSafe(const std::string& field) {
    // Reject the characters/sequences injection relies on.
    const std::string forbidden[] = {"'", "\"", ";", "--", "/*", "*/"};
    for (const std::string& bad : forbidden) {
        if (field.find(bad) != std::string::npos) return false;
    }
    return true;
}

bool safeLogin(const std::string& username, const std::string& password,
               bool& rejectedByValidation) {
    rejectedByValidation = false;

    // Defense 2: validate first.
    if (!inputLooksSafe(username) || !inputLooksSafe(password)) {
        rejectedByValidation = true;
        return false;
    }

    // Defense 1: parameterized lookup. The inputs are compared as plain
    // data against each row -- no query string is ever built from them,
    // so there's no syntax for an attacker to inject INTO.
    for (const UserRow& row : usersTable()) {
        if (row.username == username && row.password == password) {
            return true;
        }
    }
    return false;
}

void showResult(bool success) {
    std::cout << (success ? "    >> ACCESS GRANTED\n" : "    >> access denied\n");
}

} // namespace

namespace SqlInjectionDemo {

void run() {
    const std::string attack = "' OR 1=1--";

    std::cout << "\n=== Part 1: SQL Injection ===\n";
    std::cout << "A login builds its SQL query by concatenating user input.\n"
              << "The in-memory 'database' holds: alice, bob, admin.\n";

    std::cout << "\n[A] Legitimate login on the VULNERABLE version (alice / wonderland):\n";
    showResult(vulnerableLogin("alice", "wonderland", true));

    std::cout << "\n[B] Wrong password on the VULNERABLE version (alice / guess):\n";
    showResult(vulnerableLogin("alice", "guess", true));

    std::cout << "\n[C] INJECTION on the VULNERABLE version.\n"
              << "    Username field: " << attack << "\n"
              << "    (Password is left blank -- the attacker doesn't know one.)\n";
    bool bypassed = vulnerableLogin(attack, "", true);
    showResult(bypassed);
    std::cout << "    Why: the injected  ' OR 1=1  makes the WHERE clause always\n"
              << "    true, and  --  comments out the password check entirely.\n"
              << "    The attacker is logged in without any valid credentials.\n";

    std::cout << "\n[D] The SAME injection against the SAFE version.\n"
              << "    Username field: " << attack << "\n";
    bool rejected = false;
    bool safeResult = safeLogin(attack, "", rejected);
    showResult(safeResult);
    if (rejected) {
        std::cout << "    Input validation rejected the SQL metacharacters (' and --).\n";
    }
    std::cout << "    Even if validation were removed, the parameterized lookup treats\n"
              << "    the whole string as a literal username -- which matches no row --\n"
              << "    so there is no query syntax for the attack to hijack.\n";

    std::cout << "\n[E] Legitimate login still works on the SAFE version (alice / wonderland):\n";
    bool ignore = false;
    showResult(safeLogin("alice", "wonderland", ignore));

    std::cout << "\nTakeaway: never build queries by string concatenation. Use\n"
              << "parameterized queries (prepared statements); validate input as a\n"
              << "second layer, never as the only one.\n";
}

} // namespace SqlInjectionDemo
