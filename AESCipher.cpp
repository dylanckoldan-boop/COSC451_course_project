#include "AESCipher.h"
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <stdexcept>

std::string AESCipher::encrypt(const std::string& plaintext, const std::string& key) const {
    using namespace CryptoPP;

    // Fresh random IV per call -- CBC mode requires a unique IV each time
    // to avoid leaking patterns across messages encrypted under the same key.
    AutoSeededRandomPool rng;
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    SecByteBlock keyBytes(reinterpret_cast<const byte*>(key.data()), key.size());

    std::string cipherBytes;
    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(keyBytes, keyBytes.size(), iv, sizeof(iv));

    StringSource(plaintext, true,
        new StreamTransformationFilter(encryptor,
            new StringSink(cipherBytes)
        ) // PKCS#7 padding is StreamTransformationFilter's default behavior
    );

    // Prepend the IV so decrypt() can recover it -- an IV isn't secret,
    // it just has to be known at decryption time, so shipping it
    // alongside the ciphertext (rather than out-of-band) is standard practice.
    std::string result(reinterpret_cast<char*>(iv), sizeof(iv));
    result += cipherBytes;
    return result;
}

std::string AESCipher::decrypt(const std::string& ciphertext, const std::string& key) const {
    using namespace CryptoPP;

    if (ciphertext.size() < AES::BLOCKSIZE) {
        throw std::invalid_argument("Ciphertext too short to contain an IV.");
    }

    const byte* ivBytes = reinterpret_cast<const byte*>(ciphertext.data());
    std::string actualCipher = ciphertext.substr(AES::BLOCKSIZE);

    SecByteBlock keyBytes(reinterpret_cast<const byte*>(key.data()), key.size());

    std::string recovered;
    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(keyBytes, keyBytes.size(), ivBytes, AES::BLOCKSIZE);

    // Throws CryptoPP::Exception if the PKCS7 padding check fails -- which
    // is exactly what happens when the wrong key is used. Callers (like
    // ConversationVault) catch this to distinguish "wrong key" from a crash.
    StringSource(actualCipher, true,
        new StreamTransformationFilter(decryptor,
            new StringSink(recovered)
        )
    );

    return recovered;
}
