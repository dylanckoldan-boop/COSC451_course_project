#pragma once
#include <string>
#include <vector>

/*
 * HexUtil
 * -------
 * Small helpers shared by UserStore (accounts.db) and ChatHistory
 * (chat_log.db). Every field written to either file is hex-encoded
 * first, because several fields are raw binary -- AES ciphertext, AES
 * session keys, password salts and hashes -- and raw binary can contain
 * tabs, newlines, or null bytes that would break a line-based text
 * format. Hex output only ever contains 0-9 and a-f, so tabs and
 * newlines are always safe to use as field and record separators.
 */
namespace HexUtil {

inline std::string toHex(const std::string& raw) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(raw.size() * 2);
    for (unsigned char c : raw) {
        out += digits[c >> 4];   // high 4 bits
        out += digits[c & 0x0F]; // low 4 bits
    }
    return out;
}

inline int hexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1; // not a hex digit
}

// Returns false (leaving `out` unspecified) if `hex` isn't valid hex --
// callers treat that as a corrupted file rather than guessing.
inline bool fromHex(const std::string& hex, std::string& out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hexValue(hex[i]);
        int lo = hexValue(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out += static_cast<char>((hi << 4) | lo);
    }
    return true;
}

// Splits on a single delimiter character. "a,,b" -> {"a", "", "b"}; an
// empty input string yields one empty element, so callers skip empties
// where that matters (e.g. an account with no contacts).
inline std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::string current;
    for (char c : s) {
        if (c == delim) {
            parts.push_back(current);
            current.clear();
        } else {
            current += c;
        }
    }
    parts.push_back(current);
    return parts;
}

// Windows text files may leave a trailing '\r' on lines read by getline.
inline void stripCR(std::string& line) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
}

} // namespace HexUtil
