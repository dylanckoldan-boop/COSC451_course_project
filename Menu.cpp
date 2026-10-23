#include "Menu.h"
#include "CaesarCipher.h"
#include "VigenereCipher.h"
#include "DESCipher.h"
#include "DESKey.h"
#include "AESCipher.h"
#include "AESKey.h"
#include "ConversationVault.h"
#include "Message.h"
#include "MessageChannel.h"
#include <iostream>
#include <limits>
#include <chrono>
#include <cmath>
#include <iomanip>
#include "RSAKeys.h"
#include "RSACipher.h"
#include "HybridCrypto.h"
#include "HexUtil.h"
#include "SSLScenarios.h"
#include "SqlInjectionDemo.h"
#include "BufferOverflowDemo.h"
#include "PayloadSimDemo.h"
#include <cryptopp/osrng.h>

namespace {
    // Reads a numeric menu selection without the Week 1 infinite-loop bug.
    // `std::cin >> choice` on non-numeric input (e.g. "abc") puts cin into
    // a FAILED state and leaves the bad text in the buffer -- every later
    // read then fails instantly, so the menu printed "Invalid option"
    // forever. This clears the failure flag and discards the rest of the
    // line so the next prompt starts clean.
    //
    // Returns: the number typed, 0 for invalid input (callers' `default:`
    // case already handles 0 as "Invalid option"), or -1 if input has
    // closed entirely (end of file / Ctrl+Z on Windows / piped input ran
    // out), which callers treat as "exit" instead of looping forever.
    int readMenuChoice() {
        int choice = 0;
        if (std::cin >> choice) {
            return choice;
        }
        if (std::cin.eof()) {
            return -1;
        }
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return 0;
    }

    // Week 6: SSL handshake simulation submenu. Doesn't need an account --
    // it simulates its own client, server, CAs, and attacker.
    void runSSLSimulationMenu() {
        std::cout << "\n--- SSL Handshake Simulation ---\n"
                  << "1. Honest handshake, RSA key exchange (detailed log)\n"
                  << "2. Honest handshake, DHE key exchange (detailed log)\n"
                  << "3. Attack scenarios (detailed log)\n"
                  << "4. Full test suite (pass/fail summary + RSA vs DHE timing)\n"
                  << "Select an option: ";
        switch (readMenuChoice()) {
            case 1: SSLScenarios::runHonestHandshake(false); break;
            case 2: SSLScenarios::runHonestHandshake(true); break;
            case 3: SSLScenarios::runAttackScenarios(true); break;
            case 4: SSLScenarios::runFullSuite(); break;
            default: std::cout << "Invalid option.\n"; break;
        }
    }

    // Week 7: Security Demos submenu. Self-contained -- no account
    // needed, same pattern as the SSL simulation option.
    void runSecurityDemosMenu() {
        std::cout << "\n--- Security Demos (Attacks & Defenses) ---\n"
                  << "1. SQL Injection (vulnerable vs. parameterized)\n"
                  << "2. Buffer Overflow (simulated)\n"
                  << "3. Virus Payload Simulation (benign)\n"
                  << "4. Run all three\n"
                  << "Select an option: ";
        switch (readMenuChoice()) {
            case 1: SqlInjectionDemo::run(); break;
            case 2: BufferOverflowDemo::run(); break;
            case 3: PayloadSimDemo::run(); break;
            case 4:
                SqlInjectionDemo::run();
                BufferOverflowDemo::run();
                PayloadSimDemo::run();
                break;
            default: std::cout << "Invalid option.\n"; break;
        }
    }
}

void Menu::printUserGuide() const {
    std::cout <<
        "==================================================\n"
        " Encrypted Messenger Sandbox -- User Guide\n"
        "==================================================\n"
        " 1. Create an account, then log in.\n"
        " 2. Add another account as a contact (they must already exist).\n"
        " 3. Send a message: pick a contact, pick a cipher, enter a key,\n"
        "    then type your plaintext message.\n"
        " 4. The app will show you the ciphertext AND decrypt it back,\n"
        "    then write both to <username>_chat_history.txt.\n"
        " 5. Seal a conversation to a shared AES-encrypted file, and open\n"
        "    it later with the same key you and your contact agreed on.\n"
        " 6. Runtimes will show the metrics for all ciphers.\n"
        " 7. SSL Handshake Simulation (main menu) demonstrates the\n"
        "    handshake, certificate checks, and attacks being rejected.\n"
        " 8. Accounts, RSA keys, contacts, and chat history are saved\n"
        "    between sessions (accounts.db / chat_log.db).\n"
        "==================================================\n\n";
}

void Menu::printLoggedOutMenu() const {
    std::cout << "\n--- Main Menu ---\n"
              << "1. Create Account\n"
              << "2. Login\n"
              << "3. Exit\n"
              << "4. Runtimes\n"
              << "5. SSL Handshake Simulation\n"
              << "6. Security Demos (Attacks & Defenses)\n"
              << "Select an option: ";
}

void Menu::printLoggedInMenu() const {
    std::cout << "\n--- Logged in as " << currentUser->getUsername() << " ---\n"
              << "1. View Contacts\n"
              << "2. Add Contact\n"
              << "3. Send Message\n"
              << "4. View Chat History\n"
              << "5. Seal Conversation to Shared File\n"
              << "6. Open Shared Conversation File\n"
              << "7. Logout\n"
              << "Select an option: ";
}

//edit: 9/16/26
// add the void printRuntimes()
// cleaned up 9/17/26: same 4 ciphers x 4 sizes (1/10/100/1000 KB) and same
// steady_clock timing as before -- only the table construction changed.
//edit: 10/1/26 -- added the hybrid RSA+AES benchmark section below the
// original table, per the note left here. RSA itself only ever wraps a
// fixed 32-byte AES session key, never the bulk testtext -- so its own
// encrypt/decrypt timings are expected to stay roughly FLAT across all 4
// row sizes (unlike every symmetric cipher above, which scales with
// size). That's not a bug, it's the entire point: RSA's cost is
// independent of message size, which is exactly why it's only ever used
// to wrap a short session key rather than bulk data.
void Menu::printRuntimes() {
    const int sizeCount = 4;   // 1 KB, 10 KB, 100 KB, 1000 KB
    const int cipherCount = 4; // Caesar, Vigenere, DES, AES

    const int wAlgo = 18, wSize = 12, wEnc = 22, wDec = 22;
    const int totalWidth = wAlgo + wSize + wEnc + wDec;

    std::cout << "\n" << std::string(totalWidth, '=') << "\n";
    std::cout << std::left
              << std::setw(wAlgo) << "Algorithm"
              << std::setw(wSize) << "File Size"
              << std::setw(wEnc)  << "Encrypt Time (s)"
              << std::setw(wDec)  << "Decrypt Time (s)" << "\n";
    std::cout << std::string(totalWidth, '-') << "\n";
    std::cout << std::fixed << std::setprecision(6);

    for (int f = 0; f < sizeCount; f++) {
        int filesize = 1024 * static_cast<int>(std::pow(10, f));
        std::string testtext(filesize, '5');

        for (int i = 0; i < cipherCount; i++) {
            std::unique_ptr<Cipher> cipher;
            std::string testkey;

            switch (i) {
                case 0: cipher = std::make_unique<CaesarCipher>();   testkey = "3"; break;
                case 1: cipher = std::make_unique<VigenereCipher>(); testkey = "three"; break;
                case 2: cipher = std::make_unique<DESCipher>();      testkey = "12345678"; break;
                case 3: cipher = std::make_unique<AESCipher>();      testkey = "0123456789abcdeffedcba9876543210"; break;
            }

            std::chrono::steady_clock::time_point start1 = std::chrono::steady_clock::now();
            std::string ciphertext = cipher->encrypt(testtext, testkey);
            std::chrono::steady_clock::time_point end1 = std::chrono::steady_clock::now();
            std::chrono::duration<double> encryptSeconds = end1 - start1;

            std::chrono::steady_clock::time_point start2 = std::chrono::steady_clock::now();
            std::string roundTrip = cipher->decrypt(ciphertext, testkey);
            std::chrono::steady_clock::time_point end2 = std::chrono::steady_clock::now();
            std::chrono::duration<double> decryptSeconds = end2 - start2;

            std::string sizeLabel = std::to_string(filesize / 1024) + " KB";

            std::cout << std::left
                      << std::setw(wAlgo) << cipher->name()
                      << std::setw(wSize) << sizeLabel
                      << std::setw(wEnc)  << encryptSeconds.count()
                      << std::setw(wDec)  << decryptSeconds.count() << "\n";
        }
    }
    std::cout << std::string(totalWidth, '=') << "\n\n";

    // --- Hybrid RSA+AES section ---
    // RSA key generation happens ONCE here (not per row) -- in a real
    // system you'd never regenerate an identity keypair per message,
    // and keygen's cost is worth reporting on its own since prime search
    // is often the slowest single step in the whole RSA pipeline.
    std::cout << "=== Hybrid RSA+AES (RSA wraps a 32-byte AES session key; AES does the bulk work) ===\n";

    std::chrono::steady_clock::time_point keygenStart = std::chrono::steady_clock::now();
    RSAKeyPair rsaKeys = RSAKeys::generate(2048);
    std::chrono::steady_clock::time_point keygenEnd = std::chrono::steady_clock::now();
    std::chrono::duration<double> keygenSeconds = keygenEnd - keygenStart;
    std::cout << "RSA-2048 key generation took " << keygenSeconds.count() << " s\n\n";

    std::cout << std::left
              << std::setw(wAlgo) << "Algorithm"
              << std::setw(wSize) << "File Size"
              << std::setw(wEnc)  << "Encrypt Time (s)"
              << std::setw(wDec)  << "Decrypt Time (s)" << "\n";
    std::cout << std::string(totalWidth, '-') << "\n";

    for (int f = 0; f < sizeCount; f++) {
        int filesize = 1024 * static_cast<int>(std::pow(10, f));
        std::string testtext(filesize, '5');
        std::string sizeLabel = std::to_string(filesize / 1024) + " KB";

        // Fresh random 32-byte AES session key each row (not user-typed --
        // this is what a real hybrid scheme generates per-message).
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::byte sessionKeyBytes[32];
        rng.GenerateBlock(sessionKeyBytes, sizeof(sessionKeyBytes));
        std::string aesKey(reinterpret_cast<char*>(sessionKeyBytes), sizeof(sessionKeyBytes));

        // RSA wraps/unwraps the session key -- cost independent of filesize.
        std::chrono::steady_clock::time_point startRSAEnc = std::chrono::steady_clock::now();
        std::string encryptedAESKey = RSAEncrypt(aesKey, rsaKeys.e, rsaKeys.n);
        std::chrono::steady_clock::time_point endRSAEnc = std::chrono::steady_clock::now();
        std::chrono::duration<double> rsaEncryptSeconds = endRSAEnc - startRSAEnc;

        std::chrono::steady_clock::time_point startRSADec = std::chrono::steady_clock::now();
        std::string decryptedAESKey = RSADecrypt(encryptedAESKey, rsaKeys.d, rsaKeys.n);
        std::chrono::steady_clock::time_point endRSADec = std::chrono::steady_clock::now();
        std::chrono::duration<double> rsaDecryptSeconds = endRSADec - startRSADec;

        std::cout << std::left
                  << std::setw(wAlgo) << "RSA (key wrap)"
                  << std::setw(wSize) << sizeLabel
                  << std::setw(wEnc)  << rsaEncryptSeconds.count()
                  << std::setw(wDec)  << rsaDecryptSeconds.count() << "\n";

        // Confirm RSA actually recovered the session key before timing AES
        // with it. restoreSessionKeyLength puts back any leading zero bytes
        // textbook RSA dropped (see HybridCrypto.h). The equality check
        // matters because a WRONG key restored to 32 bytes would still let
        // AES encrypt and decrypt "successfully" with itself -- silently
        // reporting a pass even though the RSA step failed.
        if (!HybridCrypto::restoreSessionKeyLength(decryptedAESKey) || decryptedAESKey != aesKey) {
            std::cout << std::left << std::setw(wAlgo) << "AES (bulk data)" << std::setw(wSize) << sizeLabel
                      << "SKIPPED -- RSA did not recover the session key (is `d` implemented?)\n";
            continue;
        }

        // AES does the actual bulk encrypt/decrypt of testtext, using the
        // session key RSA just wrapped/unwrapped.
        try {
            AESCipher aesCipher;
            std::chrono::steady_clock::time_point startAESEnc = std::chrono::steady_clock::now();
            std::string ciphertext = aesCipher.encrypt(testtext, decryptedAESKey);
            std::chrono::steady_clock::time_point endAESEnc = std::chrono::steady_clock::now();
            std::chrono::duration<double> aesEncryptSeconds = endAESEnc - startAESEnc;

            std::chrono::steady_clock::time_point startAESDec = std::chrono::steady_clock::now();
            std::string roundTrip = aesCipher.decrypt(ciphertext, decryptedAESKey);
            std::chrono::steady_clock::time_point endAESDec = std::chrono::steady_clock::now();
            std::chrono::duration<double> aesDecryptSeconds = endAESDec - startAESDec;

            std::cout << std::left
                      << std::setw(wAlgo) << "AES (bulk data)"
                      << std::setw(wSize) << sizeLabel
                      << std::setw(wEnc)  << aesEncryptSeconds.count()
                      << std::setw(wDec)  << aesDecryptSeconds.count() << "\n";
        } catch (const std::exception& ex) {
            std::cout << std::left << std::setw(wAlgo) << "AES (bulk data)" << std::setw(wSize) << sizeLabel
                      << "FAILED (" << ex.what() << ")\n";
        }
    }
    std::cout << std::string(totalWidth, '=') << "\n\n";
}

void Menu::handleCreateAccount() {
    std::string username, password;
    std::cout << "New username: ";
    std::cin >> username;
    std::cout << "New password: ";
    std::cin >> password;

    if (accountManager.createAccount(username, password)) {
        Account* acc = accountManager.findAccount(username);
        std::cout << "Account created. You can now log in.\n";
        std::cout << "RSA public key generated for this account:\n  " << acc->getPublicKey() << "\n";
        // Persist immediately so the new account (and its RSA keypair)
        // survives even if the program is closed right after.
        if (!accountManager.saveToDisk()) {
            std::cout << "[Warning] Could not save accounts.db -- this account won't survive a restart.\n";
        }
    } else {
        std::cout << "That username already exists.\n";
    }
}

void Menu::handleLogin() {
    std::string username, password;
    std::cout << "Username: ";
    std::cin >> username;
    std::cout << "Password: ";
    std::cin >> password;

    Account* acc = accountManager.login(username, password);
    if (acc == nullptr) {
        std::cout << "Login failed: invalid username or password.\n";
        return;
    }
    currentUser = acc;
    std::cout << "Welcome, " << currentUser->getUsername() << "!\n";
    if (!currentUser->isUnlocked()) {
        // Password matched but the stored private key wouldn't decrypt --
        // accounts.db has been altered. Login proceeds, but this account's
        // RSA-encrypted messages can't be read this session.
        std::cout << "[Warning] Your private key could not be unlocked (accounts.db may have been\n"
                  << "          modified). RSA-encrypted messages can't be read this session.\n";
    }
}

void Menu::handleLogout() {
    std::cout << "Logging out " << currentUser->getUsername() << ".\n";
    // Wipe the decrypted private key from memory -- after this, no code
    // can read this account's RSA messages until the user logs in again.
    currentUser->lockPrivateKey();
    currentUser = nullptr;
}

void Menu::handleAddContact() {
    std::string contactUsername;
    std::cout << "Username to add as a contact: ";
    std::cin >> contactUsername;

    if (contactUsername == currentUser->getUsername()) {
        std::cout << "You can't add yourself as a contact.\n";
        return;
    }
    if (!accountManager.accountExists(contactUsername)) {
        std::cout << "No such account exists.\n";
        return;
    }
    currentUser->addContact(contactUsername);
    std::cout << contactUsername << " added to your contact list.\n";
    if (!accountManager.saveToDisk()) {
        std::cout << "[Warning] Could not save accounts.db -- this contact won't survive a restart.\n";
    }
}

void Menu::handleViewContacts() const {
    const auto& contacts = currentUser->getContacts();
    if (contacts.empty()) {
        std::cout << "Your contact list is empty.\n";
        return;
    }
    std::cout << "Your contacts:\n";
    for (const std::string& c : contacts) {
        std::cout << "  - " << c << "\n";
    }
}

std::unique_ptr<Cipher> Menu::chooseCipher() const {
    std::cout << "Choose a cipher:\n  1. Caesar Cipher\n  2. Vigenere Cipher\n  3. DES\n  4. AES\n  5. RSA (hybrid session-key exchange)\nSelection: ";
    int choice = readMenuChoice(); // invalid or closed input falls through to Caesar

    if (choice == 2) return std::make_unique<VigenereCipher>();
    if (choice == 3) return std::make_unique<DESCipher>();
    if (choice == 4) return std::make_unique<AESCipher>();
    if (choice == 5) return std::make_unique<RSACipher>();
    return std::make_unique<CaesarCipher>();
}

void Menu::handleSendMessage() {
    const auto& contacts = currentUser->getContacts();
    if (contacts.empty()) {
        std::cout << "You have no contacts yet. Add one first.\n";
        return;
    }

    std::string receiver;
    std::cout << "Send to which contact?: ";
    std::cin >> receiver;
    if (!currentUser->isContact(receiver)) {
        std::cout << receiver << " is not in your contact list.\n";
        return;
    }

    std::unique_ptr<Cipher> cipher = chooseCipher();

    // --- RSA: real end-to-end hybrid flow (see HybridCrypto.h) ---
    // The sender only ever touches PUBLIC keys (the receiver's and their
    // own). Nobody's private key is used here except the sender's own --
    // and only to show the sender their own copy, which they're entitled
    // to read. The receiver decrypts later, at THEIR login, with THEIR
    // private key (handleViewChatHistory). This replaces the old sandbox
    // shortcut that reached into the receiver's account.
    if (cipher->name() == "RSA") {
        Account* receiverAcct = accountManager.findAccount(receiver);
        if (receiverAcct == nullptr) {
            std::cout << "Could not find " << receiver << "'s account.\n";
            return;
        }

        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::string plaintext;
        std::cout << "Enter your message: ";
        std::getline(std::cin, plaintext);

        std::string ciphertext, keyField;
        try {
            HybridCrypto::seal(plaintext, receiverAcct->getPublicKey(),
                               currentUser->getPublicKey(), ciphertext, keyField);
        } catch (const std::exception& ex) {
            std::cout << "Could not encrypt message: " << ex.what() << "\n";
            return;
        }

        ++messageCounter;
        // Plaintext deliberately stored EMPTY -- only ciphertext and the
        // two RSA-wrapped session keys are kept or written to disk.
        Message msg(currentUser->getUsername(), receiver, "", ciphertext,
                    HybridCrypto::label(), keyField, "msg#" + std::to_string(messageCounter));

        std::cout << "\n--- Encryption Result (" << HybridCrypto::label() << ") ---\n";
        std::cout << "Receiver's public key    : " << receiverAcct->getPublicKey().substr(0, 48) << "...\n";
        std::cout << "Session key wrapped for " << receiver << " and for you (both stored, neither readable without a private key)\n";
        std::cout << "Ciphertext (AES, hex)    : " << HexUtil::toHex(ciphertext) << "\n";

        std::string myCopy;
        if (HybridCrypto::open(msg, currentUser->getUsername(), currentUser->getPrivateKey(), myCopy)) {
            std::cout << "Your copy, decrypted with YOUR private key: " << myCopy << "\n";
        } else {
            std::cout << "Could not decrypt your own copy -- if RSAKeys.cpp's `d` isn't implemented\n"
                      << "yet, that's expected. The message is still saved, encrypted.\n";
        }
        std::cout << receiver << " can read it after logging in (View Chat History).\n";

        MessageChannel::send(msg, chatHistory);
        chatHistory.writeToFile(msg.sender);
        chatHistory.writeToFile(msg.receiver);
        return;
    }

    std::string key;

    if (cipher->name() == "DES") {
        while (true) {
            std::string rawKeyInput;
            std::cout << "Enter a DES key: ";
            std::cin >> rawKeyInput;

            DESKey desKey(rawKeyInput);
            if (desKey.isValid()) {
                key = desKey.getKeyMaterial();
                break;
            }
            std::cout << "Invalid DES key: " << desKey.getValidationError() << " Try again.\n";
        }
    } else if (cipher->name() == "AES") {
        while (true) {
            std::string rawKeyInput;
            std::cout << "Enter an AES key: ";
            std::cin >> rawKeyInput;

            AESKey aesKey(rawKeyInput);
            if (aesKey.isValid()) {
                key = aesKey.getKeyMaterial();
                break;
            }
            std::cout << "Invalid AES key: " << aesKey.getValidationError() << " Try again.\n";
        }
    } else {
        std::cout << "Enter the key (shift number for Caesar, keyword for Vigenere): ";
        std::cin >> key;
    }

    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::string plaintext;
    std::cout << "Enter your message: ";
    std::getline(std::cin, plaintext);

    std::string ciphertext = cipher->encrypt(plaintext, key);
    std::string roundTrip = cipher->decrypt(ciphertext, key);

    std::cout << "\n--- Encryption Result (" << cipher->name() << ") ---\n";
    std::cout << "Plaintext  : " << plaintext << "\n";
    std::cout << "Ciphertext : " << ciphertext << "\n";
    std::cout << "Decrypted  : " << roundTrip << "\n";

    ++messageCounter;
    Message msg(currentUser->getUsername(), receiver, plaintext, ciphertext,
                cipher->name(), key, "msg#" + std::to_string(messageCounter));

    MessageChannel::send(msg, chatHistory);
    chatHistory.writeToFile(msg.sender);
    chatHistory.writeToFile(msg.receiver);
}

void Menu::handleViewChatHistory() {
    const auto& history = chatHistory.getHistoryFor(currentUser->getUsername());
    if (history.empty()) {
        std::cout << "No chat history yet.\n";
        return;
    }
    for (const Message& msg : history) {
        std::string direction = (msg.sender == currentUser->getUsername())
                                     ? "SENT TO " + msg.receiver
                                     : "RECEIVED FROM " + msg.sender;
        std::cout << "[" << msg.timestamp << "] " << direction << "\n";

        if (msg.cipherName == HybridCrypto::label()) {
            // The receiver-side half of the hybrid flow: decrypted HERE,
            // only now that this participant is logged in, using their
            // own private key.
            std::string recovered;
            std::cout << "  Cipher: " << msg.cipherName << "\n";
            if (HybridCrypto::open(msg, currentUser->getUsername(), currentUser->getPrivateKey(), recovered)) {
                std::cout << "  Plaintext : " << recovered << "  (decrypted with your private key)\n";
            } else {
                std::cout << "  Plaintext : [could not decrypt with your private key]\n";
            }
            std::cout << "  Ciphertext: " << HexUtil::toHex(msg.ciphertext) << "\n";
        } else {
            std::cout << "  Cipher: " << msg.cipherName << " (key: " << msg.key << ")\n"
                      << "  Plaintext : " << msg.plaintext << "\n"
                      << "  Ciphertext: " << msg.ciphertext << "\n";
        }
    }
    chatHistory.writeToFile(currentUser->getUsername());
}

void Menu::handleSealConversation() {
    std::string otherUser;
    std::cout << "Seal a shared file with which contact?: ";
    std::cin >> otherUser;
    if (!currentUser->isContact(otherUser)) {
        std::cout << otherUser << " is not in your contact list.\n";
        return;
    }

    std::string rawKeyInput;
    std::cout << "Enter a shared AES key (both you and " << otherUser
              << " will need this same key to open it later): ";
    std::cin >> rawKeyInput;

    AESKey aesKey(rawKeyInput);
    if (!aesKey.isValid()) {
        std::cout << "Invalid AES key: " << aesKey.getValidationError() << "\n";
        return;
    }

    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::string content;
    std::cout << "Enter the content to seal into the shared file: ";
    std::getline(std::cin, content);

    ConversationVault::seal(currentUser->getUsername(), otherUser, aesKey.getKeyMaterial(), content);
    std::cout << "Sealed. " << otherUser << " can open this later with the same key.\n";
}

void Menu::handleOpenConversation() {
    std::string otherUser;
    std::cout << "Open the shared file with which contact?: ";
    std::cin >> otherUser;

    std::string rawKeyInput;
    std::cout << "Enter the shared AES key: ";
    std::cin >> rawKeyInput;

    AESKey aesKey(rawKeyInput);
    if (!aesKey.isValid()) {
        std::cout << "Invalid AES key: " << aesKey.getValidationError() << "\n";
        return;
    }

    std::string content;
    if (ConversationVault::open(currentUser->getUsername(), otherUser, aesKey.getKeyMaterial(), content)) {
        std::cout << "\n--- Shared File Contents ---\n" << content << "\n";
    } else {
        std::cout << "Could not open: wrong key, or no shared file exists yet for you and "
                  << otherUser << ".\n";
    }
}

void Menu::run() {
    printUserGuide();

    // Restore everything saved by previous sessions before showing menus.
    StoreLoadResult accountsLoad = accountManager.loadFromDisk();
    if (accountsLoad == StoreLoadResult::Unreadable) {
        std::cout << "[Warning] accounts.db was unreadable and has been set aside as\n"
                  << "          accounts.db.unreadable. Starting with no saved accounts.\n";
    } else if (accountsLoad == StoreLoadResult::LegacyFormat) {
        std::cout << "[Notice] accounts.db is from the earlier format, which stored private keys\n"
                  << "         UNENCRYPTED. It has been moved to accounts.db.v1-backup.\n"
                  << "         Please recreate your accounts, then delete that backup file.\n";
    }
    if (!chatHistory.loadFromDisk()) {
        std::cout << "[Warning] chat_log.db was unreadable and has been set aside as\n"
                  << "          chat_log.db.unreadable. Starting with empty history.\n";
    }
    // Resume numbering where the last session left off, so timestamps
    // stay unique (msg#1 from a previous run isn't reused).
    messageCounter = static_cast<int>(chatHistory.messageCount());
    std::cout << "Loaded " << accountManager.accountCount() << " account(s) and "
              << chatHistory.messageCount() << " message(s) from previous sessions.\n";

    bool running = true;
    while (running) {
        if (currentUser == nullptr) {
            printLoggedOutMenu();
            int choice = readMenuChoice();
            switch (choice) {
                case -1: running = false; break; // input closed -- exit instead of looping
                case 1: handleCreateAccount(); break;
                case 2: handleLogin(); break;
                case 3: running = false; break;
                case 4: printRuntimes(); break;
                case 5: runSSLSimulationMenu(); break;
                case 6: runSecurityDemosMenu(); break;
                default: std::cout << "Invalid option.\n"; break;
            }
        } else {
            printLoggedInMenu();
            int choice = readMenuChoice();
            switch (choice) {
                case -1: // input closed -- lock the key and exit instead of looping
                    currentUser->lockPrivateKey();
                    running = false;
                    break;
                case 1: handleViewContacts(); break;
                case 2: handleAddContact(); break;
                case 3: handleSendMessage(); break;
                case 4: handleViewChatHistory(); break;
                case 5: handleSealConversation(); break;
                case 6: handleOpenConversation(); break;
                case 7: handleLogout(); break;
                default: std::cout << "Invalid option.\n"; break;
            }
        }
    }

    std::cout << "Goodbye.\n";
}
