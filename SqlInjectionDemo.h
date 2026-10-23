#pragma once

/*
 * SqlInjectionDemo
 * ----------------
 * Week 7, Part 1. Demonstrates SQL injection against a VULNERABLE login
 * that builds its query by string concatenation, then shows the same
 * login made safe with a parameterized query + input validation.
 *
 * There is no real database here -- a tiny in-memory "users table"
 * (a std::vector of rows) plays that role, and a deliberately naive
 * query "engine" interprets the resulting SQL-like string. That's enough
 * to show HOW the classic ' OR 1=1-- payload subverts the query's logic,
 * which is the point, without depending on sqlite or any SQL server.
 *
 * Called from Menu's "Security Demos" submenu. All output is printed;
 * nothing is persisted and no account state is touched.
 */
namespace SqlInjectionDemo {

// Runs the full demonstration: shows a normal login, then the injection
// bypass against the vulnerable version, then the same attack defeated by
// the parameterized/validated version.
void run();

} // namespace SqlInjectionDemo
