#include "MessageChannel.h"
#include <iostream>

void MessageChannel::send(const Message& msg, ChatHistory& history) {
    // --- INTERCEPTION POINT --------------------------------------------
    // Later weeks: insert intrusion-prevention checks, simulated
    // tampering/inspection, or additional logging at this exact spot.
    // Nothing above or below this class needs to change when you do.
    // ---------------------------------------------------------------------

    std::cout << "[MessageChannel] Transmitting message from "
              << msg.sender << " to " << msg.receiver << "...\n";

    history.addMessage(msg);
}
