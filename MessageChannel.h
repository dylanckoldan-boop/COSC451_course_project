#pragma once
#include "Message.h"
#include "ChatHistory.h"

/*
 * MessageChannel
 * --------------
 * Represents the "wire" a Message crosses between sender and receiver.
 * This class exists ON PURPOSE as a single choke point for message
 * transit -- Menu never hands a Message directly to ChatHistory. This is
 * where you can later plug in network-security measures, intrusion
 * detection/prevention, or traffic manipulation for future weeks' units,
 * without touching Account, Message, ChatHistory, or Menu.
 *
 * Data travels: Menu builds a Message (ciphertext already computed) ->
 * calls MessageChannel::send() -> [future weeks' security hooks live
 * here] -> the message is logged into ChatHistory for both endpoints.
 */
class MessageChannel {
public:
    static void send(const Message& msg, ChatHistory& history);
};
