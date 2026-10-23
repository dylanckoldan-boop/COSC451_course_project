#include "HybridCrypto.h"
#include "RSACipher.h"
#include "AESCipher.h"
#include <cryptopp/osrng.h>
#include <exception>

namespace {
    const size_t SESSION_KEY_BYTES = 32; // AES-256
}

std::string HybridCrypto::label() {
    return "RSA+AES Hybrid";
}

bool HybridCrypto::restoreSessionKeyLength(std::string& unwrappedKey) {
    if (unwrappedKey.size() > SESSION_KEY_BYTES) {
        return false; // can't be a valid session key -- wrong private key
    }
    unwrappedKey.insert(0, SESSION_KEY_BYTES - unwrappedKey.size(), '\0');
    return true;
}

void HybridCrypto::seal(const std::string& plaintext,
                        const std::string& receiverPublicKey,
                        const std::string& senderPublicKey,
                        std::string& outCiphertext,
                        std::string& outKeyField) {
    CryptoPP::AutoSeededRandomPool rng;
    std::string sessionKey(SESSION_KEY_BYTES, '\0');
    rng.GenerateBlock(reinterpret_cast<CryptoPP::byte*>(&sessionKey[0]), sessionKey.size());

    AESCipher aes;
    outCiphertext = aes.encrypt(plaintext, sessionKey);

    RSACipher rsa;
    std::string wrappedForReceiver = rsa.encrypt(sessionKey, receiverPublicKey);
    std::string wrappedForSender = rsa.encrypt(sessionKey, senderPublicKey);
    // Both wrapped keys are decimal digits only, so '|' can't collide.
    outKeyField = wrappedForReceiver + "|" + wrappedForSender;
}

bool HybridCrypto::open(const Message& msg,
                        const std::string& viewerUsername,
                        const std::string& viewerPrivateKey,
                        std::string& outPlaintext) {
    if (viewerPrivateKey.empty()) {
        return false; // viewer's account is locked
    }

    size_t bar = msg.key.find('|');
    if (bar == std::string::npos) {
        return false; // not a key field this class produced
    }

    std::string wrapped;
    if (viewerUsername == msg.receiver) {
        wrapped = msg.key.substr(0, bar);
    } else if (viewerUsername == msg.sender) {
        wrapped = msg.key.substr(bar + 1);
    } else {
        return false; // not a participant -- no wrapped key exists for them
    }

    try {
        RSACipher rsa;
        std::string sessionKey = rsa.decrypt(wrapped, viewerPrivateKey);
        if (!restoreSessionKeyLength(sessionKey)) {
            return false;
        }
        AESCipher aes;
        outPlaintext = aes.decrypt(msg.ciphertext, sessionKey);
        return true;
    } catch (const std::exception&) {
        return false; // wrong private key (or incomplete d) fails AES's padding check
    }
}
