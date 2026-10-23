#pragma once
#include <string>
#include "Message.h"

/*
 * HybridCrypto
 * ------------
 * RSA+AES hybrid messaging, done the way real end-to-end encrypted
 * messengers do it:
 *
 *   seal (sender side):
 *     1. Generate a fresh random 32-byte AES-256 session key.
 *     2. AES-encrypt the message with it (fast, no size limit).
 *     3. RSA-wrap the session key TWICE: once with the receiver's public
 *        key, once with the sender's own public key -- so each participant
 *        can later unwrap their own copy with their own private key.
 *        (Same idea as PGP's "encrypt to self": without it, the sender
 *        couldn't read their own sent messages either.)
 *     The plaintext and the raw session key are then thrown away -- only
 *     the ciphertext and the two wrapped keys are stored.
 *
 *   open (either participant, at THEIR login):
 *     pick the wrapped key meant for the viewer, unwrap it with the
 *     viewer's OWN private key, then AES-decrypt.
 *
 * No code path ever uses one account's private key on another account's
 * behalf -- that's what retires the old sandbox shortcut.
 *
 * Storage in a Message:
 *   plaintext  -> left EMPTY on purpose (never written to disk)
 *   ciphertext -> AES output (raw bytes, IV prepended)
 *   key        -> "<wrappedForReceiver>|<wrappedForSender>" (decimal
 *                 RSA ciphertexts -- safe to store; useless without a
 *                 matching private key)
 */
class HybridCrypto {
public:
    static std::string label(); // the cipherName stored on these messages

    // Throws std::exception if a public key is malformed.
    static void seal(const std::string& plaintext,
                     const std::string& receiverPublicKey,
                     const std::string& senderPublicKey,
                     std::string& outCiphertext,
                     std::string& outKeyField);

    // Returns false on any failure (viewer isn't a participant, account
    // locked, wrong key, corrupted data) -- never throws.
    static bool open(const Message& msg,
                     const std::string& viewerUsername,
                     const std::string& viewerPrivateKey,
                     std::string& outPlaintext);

    // Textbook RSA turns the session key's bytes into one big number, so a
    // key whose first byte(s) happen to be 0x00 comes back SHORTER after
    // decryption (leading zeros vanish, like 007 becoming 7). This
    // restores them. It hits about 1 in 256 random keys -- and losing
    // byte-length information like this is one of the reasons real RSA
    // uses padding schemes such as OAEP (relevant to Part 3, question 4).
    static bool restoreSessionKeyLength(std::string& unwrappedKey);
};
