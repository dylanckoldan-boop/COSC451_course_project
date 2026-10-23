#pragma once
#include "AccountManager.h"
#include "ChatHistory.h"
#include "Cipher.h"
#include <memory>

class Menu {
private:
    AccountManager accountManager;
    ChatHistory chatHistory;
    Account* currentUser = nullptr;
    int messageCounter = 0;

    void printUserGuide() const;
    void printLoggedOutMenu() const;
    void printLoggedInMenu() const;

    void handleCreateAccount();
    void handleLogin();
    void handleLogout();
    void handleAddContact();
    void handleViewContacts() const;
    void handleSendMessage();
    void handleViewChatHistory();
    void handleSealConversation();
    void handleOpenConversation();
    void printRuntimes();

    std::unique_ptr<Cipher> chooseCipher() const;

public:
    void run();
};
