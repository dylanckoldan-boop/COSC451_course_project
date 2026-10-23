#pragma once

/*
 * PayloadSimDemo
 * --------------
 * Week 7, Part 3. A benign, educational illustration of two behaviors
 * associated with malware -- a conditional "payload" trigger and a
 * self-copy -- kept deliberately harmless.
 *
 * What this intentionally IS:
 *   - A self-copy that writes ONE labelled copy of this program's own
 *     source text into a single, named sandbox folder the user chooses,
 *     and refuses to copy again if that copy already exists (no runaway
 *     replication). Think "file named itself in one place," not "spread."
 *   - A "payload" that merely PRINTS a harmless banner when a simple
 *     condition is met (a chosen trigger date has arrived). It changes
 *     nothing, deletes nothing, hides nothing.
 *
 * What this intentionally is NOT, by design -- and what real malware does
 * that we deliberately leave out so this can't be repurposed:
 *   - It does not attach to, infect, or modify any OTHER file.
 *   - It does not spread beyond the one copy, over a network, or to other
 *     machines.
 *   - It does not install persistence, hide itself, or evade anything.
 *   - It has no harmful payload of any kind.
 *
 * The point is to make the CONCEPTS observable (a trigger condition; a
 * replication step) so the report can discuss how antivirus signatures
 * and heuristics would flag them -- not to produce anything dangerous.
 *
 * Called from Menu's "Security Demos" submenu.
 */
namespace PayloadSimDemo {

void run();

} // namespace PayloadSimDemo
