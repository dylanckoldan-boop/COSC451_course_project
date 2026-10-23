#include "CaesarCipher.h"
#include <iostream>

/*
 * *** STUDENT-OWNED FILE ***
 * TODO (Week 1): Replace both function bodies below with the real Caesar
 * cipher algorithm. `key` will arrive as a string (e.g. "3") because the
 * Cipher interface is shared with Vigenere, which needs a keyword instead
 * of a number — you'll want to std::stoi(key) to get the shift amount.
 *
 * Until you implement these, they intentionally pass text through
 * unchanged (with a console warning) so you can build/run/test the
 * account + messaging + menu system independently of the cipher logic.
 */

std::string CaesarCipher::encrypt(const std::string& plaintext, const std::string& key) const {
    //std::cout << "[CaesarCipher::encrypt] TODO not yet implemented -- returning plaintext unchanged.\n";
    /*
    * 8/28/26 Dylan Koldan 1:00 pm edit to add the cipher algorithm.
	* Create variables to hold the alphabet and the cipher alphabet. The cipher alphabet will be generated based on the key value. The key value will be used to shift the letters in the alphabet array to create the cipher alphabet.
    * -Declaring variables
	*   +keyInt is the integer value of the key string
	*   +plaintextStr is the string value of the plaintext
    *   +alphabetLower is the reference for the cipher
    *   +cipherbetLower is the shifted alphabet based on the key
	*   +aphabetUpper is the uppercase version of the alphabet for comparison
	*   +cipherbetUpper is the shifted uppercase alphabet based on the key
    */
	int keyInt = std::stoi(key);
	std::string plaintextStr = plaintext;
	char alphabetUpper[26] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
	char cipherbetUpper[26] = {};
	char alphabetLower[26] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
	char cipherbetLower[26] = {};



    /*
	* 8/28/26 Dylan Koldan 1:17 pm edit to add the cipher algorithm.
	* Create while loop to generate the cipherbet array based on the key value. The loop will iterate through the alphabet array and shift the letters based on the key value. The loop will continue until the end of the alphabet array is reached.
	* -Must use modulo operator to wrap around the alphabet array when the end is reached.
    */
	while (true) {
		for (int i = 0; i < 26; i++) {
			cipherbetUpper[i] = alphabetUpper[(i + keyInt) % 26];
			cipherbetLower[i] = alphabetLower[(i + keyInt) % 26];
		}
		break;
	}



    /*
	* 8/28/26 Dylan Koldan 1:20 pm edit to add the cipher algorithm.
	* Test input and output to console for debugging purposes.
    * -Testing inputs...
    */
	//std::cout << "Encrypting...\n";
	//std::cout << "Shift: " << keyInt << std::endl;
	//std::cout << "Plaintext: " << plaintextStr << std::endl;



    /*
	* 8/28/26 Dylan Koldan 1:25 pm edit to add the cipher algorithm.
    * Encryption Process:
	* -Iterate through the plaintextStr and compare each character to the alphabet array. If the character is found in the alphabet array, replace it with the corresponding character in the cipherbet array. If the character is not found in the alphabet array, leave it unchanged.
	*/
	for (int i = 0; i < plaintextStr.length(); i++) {
		plaintextStr[i] = (isupper(plaintextStr[i])) ? cipherbetUpper[plaintextStr[i] - 'A'] : (islower(plaintextStr[i])) ? cipherbetLower[plaintextStr[i] - 'a'] : plaintextStr[i];
	}
	




    /*
    * -Testing outputs...
    */
    //std::cout << "Encrypted...\n";
    //std::cout << "Shift: " << keyInt << std::endl;
    //std::cout << "Plaintext: " << plaintextStr << std::endl;

    return plaintextStr;
}

std::string CaesarCipher::decrypt(const std::string& ciphertext, const std::string& key) const {
    //std::cout << "[CaesarCipher::decrypt] TODO not yet implemented -- returning ciphertext unchanged.\n";
	//reverse the process of the encrypt function.
	//declare variables.
	int keyInt = std::stoi(key);
	std::string ciphertextStr = ciphertext;
	char alphabetUpper[26] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
	char cipherbetUpper[26] = {};
	char alphabetLower[26] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
	char cipherbetLower[26] = {};
	//set cipherbet.
	while (true) {
		for (int i = 0; i < 26; i++) {
			cipherbetUpper[i] = alphabetUpper[(i + keyInt) % 26];
			cipherbetLower[i] = alphabetLower[(i + keyInt) % 26];
		}
		break;
	}
	//process decryption.
	for (int i = 0; i < ciphertextStr.length(); i++) {
		ciphertextStr[i] = (isupper(ciphertextStr[i])) ? alphabetUpper[(ciphertextStr[i] - 'A' - keyInt + 26) % 26] : (islower(ciphertextStr[i])) ? alphabetLower[(ciphertextStr[i] - 'a' - keyInt + 26) % 26] : ciphertextStr[i];
	}
	//return decrypted text.
    return ciphertextStr;
}
