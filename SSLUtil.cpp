#include "SSLUtil.h"
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <ctime>
#include <sstream>
#include <vector>

namespace SSLUtil {

std::string sha256(const std::string& data) {
    std::string digest(CryptoPP::SHA256::DIGESTSIZE, '\0');
    CryptoPP::SHA256 hash;
    hash.CalculateDigest(reinterpret_cast<CryptoPP::byte*>(&digest[0]),
                         reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
    return digest;
}

std::string randomBytes(size_t count) {
    CryptoPP::AutoSeededRandomPool rng;
    std::string out(count, '\0');
    rng.GenerateBlock(reinterpret_cast<CryptoPP::byte*>(&out[0]), out.size());
    return out;
}

// localtime_s (Windows) / localtime_r (elsewhere) instead of std::localtime:
// Visual Studio's default /sdl setting turns std::localtime's
// "unsafe function" warning (C4996) into a compile ERROR.
static std::string formatDate(std::tm tm) {
    char buffer[11];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d", &tm);
    return std::string(buffer);
}

static std::tm localNow() {
    std::time_t now = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &now);
#else
    localtime_r(&now, &tm);
#endif
    return tm;
}

std::string todayISODate() {
    return formatDate(localNow());
}

std::string dateYearsFromToday(int years) {
    std::tm tm = localNow();
    tm.tm_year += years;
    std::mktime(&tm); // normalizes Feb 29 -> Mar 1 in a non-leap target year
    return formatDate(tm);
}

bool leftPad(std::string& bytes, size_t length) {
    if (bytes.size() > length) return false;
    bytes.insert(0, length - bytes.size(), '\0');
    return true;
}

std::string toDecimal(const CryptoPP::Integer& value) {
    std::ostringstream oss;
    oss << value;
    std::string s = oss.str();
    if (!s.empty() && s.back() == '.') s.pop_back(); // Crypto++'s base marker
    return s;
}

std::string toBytes(const CryptoPP::Integer& value) {
    size_t size = value.MinEncodedSize();
    std::vector<CryptoPP::byte> buffer(size);
    value.Encode(buffer.data(), size);
    return std::string(reinterpret_cast<char*>(buffer.data()), size);
}

CryptoPP::Integer fromBytes(const std::string& bytes) {
    return CryptoPP::Integer(reinterpret_cast<const CryptoPP::byte*>(bytes.data()), bytes.size());
}

CryptoPP::Integer dhGroup14Prime() {
    static const char* const PRIME_HEX =
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
    return CryptoPP::Integer((std::string("0x") + PRIME_HEX).c_str());
}

CryptoPP::Integer dhGroup14Generator() {
    return CryptoPP::Integer(2L);
}

} // namespace SSLUtil
