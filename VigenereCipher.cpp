#include "VigenereCipher.h"
#include <iostream>

/*
 * *** STUDENT-OWNED FILE ***
 * TODO (Week 1): Replace both function bodies below with the real Vigenere
 * cipher algorithm using `key` as the repeating keyword.
 * Placeholder pass-through only, so the rest of the app can be exercised.
 */

std::string VigenereCipher::encrypt(const std::string& plaintext, const std::string& key) const {
    //std::cout << "[VigenereCipher::encrypt] TODO not yet implemented -- returning plaintext unchanged.\n";
	std::string plaintextStr = plaintext;
	std::string keyStr = key;
	std::string keyStrText = "";
	std::string ciphertextStr = "";
	char alphabetUpper[26] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
	char alphabetLower[26] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
	int alphabetInt[26] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25 };
	while (true) {
		// 8/28/26 Dylan Koldan 4:20 pm edit to add the cipher algorithm.
		// while the plaintextStr is looked at, use key to fill the keyStrText to the same length as the plaintextStr. If the character in the plaintextStr is not a letter, skip it and do add to the keyStrText.
		for (int i = 0, j = 0; i < plaintextStr.length(); i++) {
			if (isalpha(plaintextStr[i])) {
				keyStrText += keyStr[j % keyStr.length()];
				j++;
			}
			else {
				keyStrText += plaintextStr[i];
			}
		}
		if (keyStrText.length() != plaintextStr.length()) {
			std::cout << "[VigenereCipher::encrypt] Error: keyStrText length does not match plaintextStr length.\n";
		}
		break;
	}
	// 8/28/26 Dylan Koldan 4:30 pm edit to add the cipher algorithm.
	// convert plaintextStr and keyStrText to individual numerical values based on the alphabet array, add them together and mod 26, then convert back to a character based on the alphabet array.
	for (int i = 0; i < plaintextStr.length(); i++) {
		//for each character in plaintextStr and keyStrText, add the numerical value according to the alphabet and mod 26, then convert back to alphabet and place into ciphertextStr
		if (isupper(plaintextStr[i])) {
			ciphertextStr += alphabetUpper[(alphabetInt[plaintextStr[i] - 'A'] + alphabetInt[toupper(keyStrText[i]) - 'A']) % 26];
		}
		else if (islower(plaintextStr[i])) {
			ciphertextStr += alphabetLower[(alphabetInt[plaintextStr[i] - 'a'] + alphabetInt[tolower(keyStrText[i]) - 'a']) % 26];
		}
		else {
			ciphertextStr += plaintextStr[i];
		}
	}
	return ciphertextStr;
}

std::string VigenereCipher::decrypt(const std::string& ciphertext, const std::string& key) const {
    //std::cout << "[VigenereCipher::decrypt] TODO not yet implemented -- returning ciphertext unchanged.\n";
	//reverse the process of the encrypt function.
	std::string ciphertextStr = ciphertext;
	char alphabetUpper[26] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
	char alphabetLower[26] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
	int alphabetInt[26] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25 };
	// 8/28/26 Dylan Koldan 4:30 pm edit to add the cipher algorithm.
	std::string keyStr = key;
	std::string keyStrText = "";
	std::string plaintextStr = "";

	//reverse
	for (int i = 0, j = 0; i < ciphertextStr.length(); i++) {
		if (isalpha(ciphertextStr[i])) {
			keyStrText += keyStr[j % keyStr.length()];
			j++;
		}
		else {
			keyStrText += ciphertextStr[i];
		}
	}
	if (keyStrText.length() != ciphertextStr.length()) {
		std::cout << "[VigenereCipher::decrypt] Error: keyStrText length does not match ciphertextStr length.\n";
	}

	//convert the ciphertextStr and keyStrText to individual numerical values based on the alphabet array, subtract them, add 26, and mod 26, then convert back to a character based on the alphabet array.
	for (int i = 0; i < ciphertextStr.length(); i++) {
		if (isupper(ciphertextStr[i])) {
			plaintextStr += alphabetUpper[(alphabetInt[ciphertextStr[i] - 'A'] - alphabetInt[toupper(keyStrText[i]) - 'A'] + 26) % 26];
		}
		else if (islower(ciphertextStr[i])) {
			plaintextStr += alphabetLower[(alphabetInt[ciphertextStr[i] - 'a'] - alphabetInt[tolower(keyStrText[i]) - 'a'] + 26) % 26];
		}
		else {
			plaintextStr += ciphertextStr[i];
		}
	}
    return plaintextStr;
}
