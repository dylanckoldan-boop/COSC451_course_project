#include "Message.h"

Message::Message(const std::string& sender, const std::string& receiver,
                  const std::string& plaintext, const std::string& ciphertext,
                  const std::string& cipherName, const std::string& key,
                  const std::string& timestamp)
    : sender(sender), receiver(receiver), plaintext(plaintext),
      ciphertext(ciphertext), cipherName(cipherName), key(key), timestamp(timestamp) {
    // Pure data-holder; no extra logic needed here by design (single
    // responsibility -- Message just carries data, it doesn't move it).
}
