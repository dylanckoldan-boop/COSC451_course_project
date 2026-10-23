#pragma once

/*
 * BufferOverflowDemo
 * ------------------
 * Week 7, Part 2 (Simulation option). Illustrates, safely and
 * observably, the core idea of a buffer overflow: writing more bytes into
 * a fixed-size buffer than it can hold spills into whatever memory sits
 * next to it, corrupting it.
 *
 * Design choice -- this SIMULATES the mechanism rather than performing a
 * real exploit. A genuine stack smash relies on undefined behavior and
 * could crash unpredictably or differ by compiler/platform; worse, a
 * working return-address hijack is exactly the weaponizable part we don't
 * want to hand out. So instead we lay two fields next to each other in a
 * struct, copy an oversized string into the first using a MANUAL,
 * BOUNDED byte loop (never a real unbounded strcpy), and let the demo
 * stop exactly at the point of corruption to show what an overflow
 * touches -- the adjacent field -- without ever running off into
 * genuinely unpredictable memory.
 *
 * Then it shows the same copy done SAFELY (bounds-checked / std::string)
 * and summarizes the standard defenses: bounds checking, stack canaries,
 * non-executable stacks/ASLR, and compiler flags like -fstack-protector.
 *
 * Called from Menu's "Security Demos" submenu. Prints only; no files, no
 * account state.
 */
namespace BufferOverflowDemo {

void run();

} // namespace BufferOverflowDemo
