#include "Menu.h"

/*
 * main
 * ----
 * Entry point. All it does is construct a Menu and hand control to it --
 * every other class in this project is exercised through Menu::run().
 * In Visual Studio: create a new empty "Windows Console Application (C++)"
 * project, add all the .h/.cpp files from this deliverable, and set this
 * file as containing main(). Build/Run (F5) to launch the console.
 */
int main() {
    Menu menu;
    menu.run();
    return 0;
}
