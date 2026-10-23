#include "DESCipher.h"
#include <iostream>
// 9/9/2026 edits: Added vector to hold 64-bit blocks of plaintext for DES encryption
#include <vector>
// 9/11/26 edit needed these for manipulating copies of the binary vectors
#include <bitset>
#include <string>
#include <array>
#include <sstream>
#include <iomanip>

/*
 * *** STUDENT-OWNED FILE ***
 * TODO (Week 2): Replace both bodies below with the real DES algorithm.
 * Placeholder pass-through only, so the DES option in the menu, the
 * DESKey validation flow, and the .txt transcript output can all be
 * built and tested before the algorithm itself exists.
 */


std::string DESCipher::encrypt(const std::string& plaintext, const std::string& key) const {
	//std::cout << "[DESCipher::encrypt] TODO not yet implemented -- returning plaintext unchanged.\n";
	// 9/10/2026 edits: Implement DES encryption algorithm here
	

    //plaintext processing
    //result 3 sets of blocks


	// Variable and function to hold 64-bit blocks of plaintext for DES encryption (pad excess)
    //also check if the plaintext is divisible by 8 and pad if not.
    std::vector<std::string> blocks;
    for (size_t i = 0; i < plaintext.size(); i += 8) {
        std::string block = plaintext.substr(i, 8);
        if (block.size() < 8) {
            int needed = 8 - block.size();
            block += std::string(needed, static_cast<char>(needed));
        }
        blocks.push_back(block);
    }
    if (plaintext.size() % 8 == 0) {
        blocks.push_back(std::string(8, static_cast<char>(8)));
    }
    //we will have 3 sets of blocks, one hex, one binary, one plaintext
    //first we need to convert the blocks into hexadecimals of the characters.
    //So first step in the loop is to take the block we are in, then convert a copy of the string from in that block, and transform it into an array of 8 char.
    std::vector<std::array<char, 8>> blockCharArrays;
    std::vector<std::string> blockBinary; // one 64-char '0'/'1' string per block
    std::vector<std::string> blockHex;    // one 16-hex-digit string per block
    //iterate the plaintext into blocks of 64 bits
    for (auto& block : blocks) {
        std::array<char, 8> chars{};
        std::string binaryStr;
        std::string hexStr;
        //create the block of 64 bits
        for (int i = 0; i < 8; i++) {
            chars[i] = block[i];
            // std::bitset<8> can be constructed directly from an integral
            // value -- casting the char to unsigned char first avoids sign
            // issues, then .to_string() gives you "01000001" style text.
            binaryStr += std::bitset<8>(static_cast<unsigned char>(block[i])).to_string();
            // stringstream with std::hex formats a byte as 2 hex digits;
            // setw(2)/setfill('0') keeps a leading zero (e.g. "0a" not "a").
            std::stringstream ss;
            ss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(static_cast<unsigned char>(block[i]));
            hexStr += ss.str();
        }
        //add the blocks to their respective vector
        blockCharArrays.push_back(chars);
        blockBinary.push_back(binaryStr);
        blockHex.push_back(hexStr);
    }


    //Test Print


    // One clean debug print per block, after it's fully built -- not nested
    // inside itself.
    //for (size_t b = 0; b < blocks.size(); b++) {
    //    std::cout << "block: " << blocks[b] << "\n";
    //    std::cout << "  binary: " << blockBinary[b] << "\n";
    //    std::cout << "  hex:    " << blockHex[b] << "\n";
    //}



























    //key processing
    //result 3 sets of key blocks
    

    // Key is already exactly 8 bytes (validated/padded by DESKey before it got
    // here) -- no splitting or padding loop needed, just one block.
    std::vector<std::string> keyBlocks;
    keyBlocks.push_back(key);
    //now the vectors
    std::vector<std::array<char, 8>> keyCharArrays;
    std::vector<std::string> keyBinary; // one 64-char '0'/'1' string
    std::vector<std::string> keyHex;    // one 16-hex-digit string
    //iterate through to get each block
    for (auto& block : keyBlocks) {
        std::array<char, 8> chars{};
        std::string binaryStr;
        std::string hexStr;
        //create the block
        for (int i = 0; i < 8; i++) {
            chars[i] = block[i];
            binaryStr += std::bitset<8>(static_cast<unsigned char>(block[i])).to_string();
            std::stringstream ss;
            ss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(static_cast<unsigned char>(block[i]));
            hexStr += ss.str();
        }
        //add the block to the vector
        keyCharArrays.push_back(chars);
        keyBinary.push_back(binaryStr);
        keyHex.push_back(hexStr);
    }


    //Test Print


    //for (size_t b = 0; b < keyBlocks.size(); b++) {
    //    std::cout << "key block: " << keyBlocks[b] << "\n";
    //    std::cout << "  binary: " << keyBinary[b] << "\n";
    //    std::cout << "  hex:    " << keyHex[b] << "\n";
    //}
















    //Round key processing
    //result 16 round keys and the 56 bit key


    //test print the binary of the key
    //std::cout << "Key: " << keyBinary[0] << std::endl;
    //standardized DES Tables
    // Make C0 and D0
    // PC-1: 64-bit key -> 56 bits (drops 8 parity bits, reorders the rest)
    const int PC1[56] = {
        57, 49, 41, 33, 25, 17,  9,
         1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
         7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4
    };
    // this table will be what rearanges the binary plaintext
    //permute key through this table
    std::string binaryPlaceholder;               // starts empty, will grow to 56 chars
    for (auto& keyBinarys : keyBinary) {
        for (int i = 0; i < 56; i++) {
            binaryPlaceholder += keyBinarys[PC1[i]-1];  // read from keyBinarys, not keyBinary
        }
        //std::cout << binaryPlaceholder << std::endl;      // 56-character result
    }
    //split the key into 28s
    std::string K_i_L;
    std::string K_i_R;
    for (int i = 0; i < 56; i++) {
        if (i < 28) {
            K_i_L += binaryPlaceholder[i];
        }
        else {
            K_i_R += binaryPlaceholder[i];
        }
    }
    //std::cout << "C0: " << K_i_L << std::endl;
    //std::cout << "D0: " << K_i_R << std::endl;


    // Left-shift amounts for C/D, one entry per round (round 1 = index 0)
    const int SHIFT_SCHEDULE[16] = {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    //getting k_1
    // PC-2: 56-bit (Ci|Di) -> 48-bit round key Ki
    const int PC2[48] = {
        14, 17, 11, 24,  1,  5,
         3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8,
        16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };
    //create round key from binaryPlaceholder
   
    
    std::vector<std::string> K_i_rounds;
    //generate 16 keys to add to the vector
    for (int i = 0; i < 16; i++) {
        std::string K_i;
        std::string K_holder1;
        std::string K_holder2;
        //come back here for proper shift scheduling
        for (int j = 0; j < 28; j++) {
            if (j + SHIFT_SCHEDULE[i] < 28) {
                K_holder1 += K_i_L[j + SHIFT_SCHEDULE[i]];
                K_holder2 += K_i_R[j + SHIFT_SCHEDULE[i]];
            }
            else {
                K_holder1 += K_i_L[(j + SHIFT_SCHEDULE[i]) % 28];
                K_holder2 += K_i_R[(j + SHIFT_SCHEDULE[i]) % 28];
            }
        }
        K_i += K_holder1;
        K_i += K_holder2;
        //within one of the 16 rounds, K_i now equals the two halves of the original key shifted by the schedule
        //create a placeholder for the round key to be stored in the vector
        std::string K_i_holder;
        for (int i = 0; i < 48; i++) {
           K_i_holder += K_i[PC2[i] - 1];
        }
        K_i_rounds.push_back(K_i_holder);


        //add the c/d shifts for proper round keys
        K_i_L = K_holder1;
        K_i_R = K_holder2;

    }

    
    //test print
    //std::cout << std::endl << "The round keys:";
    //for (auto& K_i_round : K_i_rounds) {
    //    std::cout << std::endl << K_i_round << std::endl;
    //}


    









    //R0 L0 Processing
    //BINARY COPY ONY
    //results binary copy of all blocks split by initial permutation and individually processed through Feistel


    //creating L0 and R0 from IP rotation on Plaintext Binary - same pipeline as the key geting permuted, but with this table keeping it at 64 buts and splitting into L0 and R0
    // Initial permutation: 64-bit plaintext block -> 64 bits (reordered)
    const int IP[64] = {
        58, 50, 42, 34, 26, 18, 10,  2,
        60, 52, 44, 36, 28, 20, 12,  4,
        62, 54, 46, 38, 30, 22, 14,  6,
        64, 56, 48, 40, 32, 24, 16,  8,
        57, 49, 41, 33, 25, 17,  9,  1,
        59, 51, 43, 35, 27, 19, 11,  3,
        61, 53, 45, 37, 29, 21, 13,  5,
        63, 55, 47, 39, 31, 23, 15,  7
    };
    //BBPHIP_plaintext is the inital permutation of the binary block place holder of the plaintext.  It houses what will be split after IP in each individual block
    std::vector<std::string> BBPHIP_plaintext;
    for (auto& blockBinarys : blockBinary) {
        std::string bbPlaceholder;
        for (int i = 0; i < 64; i++) {
            bbPlaceholder += blockBinarys[IP[i]-1];
        }
        BBPHIP_plaintext.push_back(bbPlaceholder);
        //std::cout << std::endl << bbPlaceholder << std::endl;
    }
    //std::cout << "Above is as follows: (1) the binary of the key (2) the removal of the parity bits down to 56 (3) the IP applied to the plaintext blocks. \n";





    //2 main operative data points
    //BBPHIP_plaintext  -> each block of plaintext in binary already underwent by the IP table still present in binary strings of 8 bytes
    //K_i_rounds        -> the 48 bit sub key from the first PC-1 and PC-2 table transformations still present in binary as a single string
    
    //auto& blocks of plaintext in binary 8 byte strings to be sectioned into left and right, placeholder the right for the next left-
    //-and then xor the binaryPlaceholder string with the expanded Right 32 bit into 48 bit by using the E-table below.






    // Final permutation: the inverse of IP, applied after round 16
    const int FP[64] = {
        40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25
    };










    // Expansion: 32-bit R -> 48 bits (some bit positions reused at boundaries)
    const int E_TABLE[48] = {
        32,  1,  2,  3,  4,  5,
         4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1
    };





    //take R0 through sboxes after the xor with 48 bit K_i





    // P: 32-bit S-box output -> 32 bits (reordered, no size change)
    const int P_TABLE[32] = {
        16,  7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26,  5, 18, 31, 10,
         2,  8, 24, 14, 32, 27,  3,  9,
        19, 13, 30,  6, 22, 11,  4, 25
    };

    // Eight S-boxes: S_BOXES[boxIndex][row][col], boxIndex 0..7, row 0..3, col 0..15
    const int S_BOXES[8][4][16] = {
        { // S1
            {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
            { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
            { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
            {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
        },
        { // S2
            {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
            { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
            { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
            {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
        },
        { // S3
            {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
            {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
            {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
            { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
        },
        { // S4
            { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
            {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
            {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
            { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
        },
        { // S5
            { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
            {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
            { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
            {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
        },
        { // S6
            {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
            {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
            { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
            { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
        },
        { // S7
            { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
            {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
            { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
            { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
        },
        { // S8
            {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
            { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
            { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
            { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
        }
    };

    //after reducing R back down to size of 32 bit, and 16 rounds of these operations, swap the left and right for the FP/inverse IP
    //next is the IP inverse

     //2 main operative data points
    //BBPHIP_plaintext  -> each block of plaintext in binary already underwent by the IP table still present in binary strings of 8 bytes
    //K_i_rounds        -> the 48 bit sub key vector from the first PC-1 and PC-2 table transformations still present in binary as a single string

    //auto& blocks of plaintext in binary 8 byte strings to be sectioned into left and right, placeholder the right for the next left-
    //-and then xor the binaryPlaceholder string with the expanded Right 32 bit into 48 bit by using the E-table below.




    //remember to send back cipher text, not plain text.  declare it.
    std::vector<std::string> BBPHIP_ciphertext;
    
    for (auto& BBPHIP_plaintexts : BBPHIP_plaintext) {
        std::string L_i;
        std::string R_i;
        for (int i = 0; i < 64; i++) {
            if (i < 32) {
                L_i += BBPHIP_plaintexts[i];
            }
            else {
                R_i += BBPHIP_plaintexts[i];
            }
        }
        //std::cout << "L0: " << L_i << std::endl;
        //std::cout << "R0: " << R_i << std::endl;
    


        //crahses??



        //at this point we have our L_0 and R_0 after initial permutation and we will operate with the full 16 round feistel structure applying a 8 sboxes to the xored values of K_i and R_i
        //after this will be the swap of the L_16 and R_16 before inverse permute.
        for (auto& K_i_round : K_i_rounds) {


            //std::cout << "\ncrash?\n";
            //feistel round the block



                std::string new_L = R_i;
                //R needs to go through expansion table
                std::string E_table_R;
                for (int i = 0; i < R_i.size(); i++) {
                    E_table_R += R_i[E_TABLE[i] - 1];
                }






                //std::cout << "\ncrash?\n";





               // std::bitset<48> ETRbits(E_table_R);
               // std::bitset<48> KIRbits(K_i_round);
               // unsigned long ETRval = ETRbits.to_ulong();
               // unsigned long KIRval = KIRbits.to_ulong();
               // unsigned long new_R_xor = ETRval ^ KIRval;
               // std::string new_R = std::to_string(new_R_xor);
                //claude assisted windows specific crash for 32 bit long overflow
                std::bitset<48> ETRbits(E_table_R);
                std::bitset<48> KIRbits(K_i_round);
                unsigned long long ETRval = ETRbits.to_ullong();
                unsigned long long KIRval = KIRbits.to_ullong();
                unsigned long long new_R_xor = ETRval ^ KIRval;
                std::string new_R = std::bitset<48>(new_R_xor).to_string();



                //std::cout << "\ncrash?\n";
                




                std::string SboxR;
                //then the 8 sboxes
                int scount = 0;
                for (int i = 0; i < 48; i += 6) {
                    std::string bb1;
                    bb1 += new_R[i];
                    bb1 += new_R[i + 5];
                    std::string bb2;
                    bb2 += new_R[i + 1];
                    bb2 += new_R[i + 2];
                    bb2 += new_R[i + 3];
                    bb2 += new_R[i + 4];
                    //convert bb1 binary 0-3
                    //convert bb2 binary 1-16
                    std::bitset<2> bits1(bb1);
                    std::bitset<4> bits2(bb2);
                    unsigned long valbit1 = bits1.to_ulong();
                    unsigned long valbit2 = bits2.to_ulong();
                    //hold the binary and convert to string
                    int selection = S_BOXES[scount][valbit1][valbit2];
                    SboxR += std::bitset<4>(selection).to_string();
                    scount++;
                }





                //std::cout << "\ncrash?\n";





                std::string frustration;
                //send frustration through the p table and paste it from SboxR lookup 
                for (int i = 0; i < 32; i++) {
                    frustration += SboxR[P_TABLE[i] - 1];
                }



                //std::cout << "\ncrash?\n";





                //std::bitset<32> LXORbits(L_i);
                //std::bitset<32> frustratingBITS(frustration);
                //unsigned long LXORval = LXORbits.to_ulong();
                //unsigned long frustratingVAL = frustratingBITS.to_ulong();
                //unsigned long LXRfrust = LXORval ^ frustratingVAL;
                //std::string GOD = std::to_string(LXRfrust);
                //R_i = GOD;
                //L_i = new_L;
                //claude helped with the same issue wrapping arround in the loop causeing decimal string avoidance from bitset constructor
                std::bitset<32> LXORbits(L_i);
                std::bitset<32> frustratingBITS(frustration);
                unsigned long LXORval = LXORbits.to_ulong();       // fine at 32 bits, no overflow risk here
                unsigned long frustratingVAL = frustratingBITS.to_ulong();
                unsigned long LXRfrust = LXORval ^ frustratingVAL;
                std::string GOD = std::bitset<32>(LXRfrust).to_string();   // <- the fix
                R_i = GOD;
                L_i = new_L;


                //std::cout << "\ncrash?\n";
                //after this crash the program crashes
            

            //std::cout << "\ncrash?\n";

            //swap each with two placeholders and permute them with inverse table and append cipherblock, write cipherblock to the ciphertext return


            




            //std::cout << "\ncrash?\n";
        }
        std::string swapR;
        std::string swapL;
        for (int i = 0; i < 32; i++) {
            swapR += L_i[i];
            swapL += R_i[i];
        }
        std::string buildPRE = swapL + swapR;
        std::string precipher;
        for (int i = 0; i < 64; i++) {
            precipher += buildPRE[FP[i] - 1];
        }


        //need to convert the precipher from binary to readable text.

        BBPHIP_ciphertext.push_back(precipher);
    }



    //std::cout << "\ncrash?\n";



    std::string ciphertext;
    for (auto& BBPHIP_ciphertexts : BBPHIP_ciphertext) {
        ciphertext += BBPHIP_ciphertexts;
    }

    //std::cout << "\ncrash?\n";



    std::string binary = ciphertext; // your full binary '0'/'1' string, e.g. the ciphertext or recovered plaintext

    std::string text;
    for (size_t i = 0; i < binary.size(); i += 8) {
        std::string eightBits = binary.substr(i, 8);              // grab one byte's worth of bits
        unsigned long value = std::bitset<8>(eightBits).to_ulong(); // parse those 8 bits as a number
        text += static_cast<char>(value);                          // reinterpret the number as a character
    }


	return text;
}










std::string DESCipher::decrypt(const std::string& ciphertext, const std::string& key) const {
    // 9/13/2026 edits: Implement DES decryption algorithm here
    // Same pipeline as encrypt(): PC-1 -> 16 round keys -> IP -> 16-round Feistel -> swap -> FP
    // The only algorithmic difference from encrypt is that the round keys get
    // applied in REVERSE order (K16, K15, ... K1) during the Feistel rounds.

    //ciphertext processing
    //ciphertext coming in should already be an exact multiple of 8 bytes
    //(it's whatever encrypt() returned), so just slice it into 8-byte blocks --
    //no padding needed here like on the plaintext side of encrypt().
    std::vector<std::string> blocks;
    for (size_t i = 0; i < ciphertext.size(); i += 8) {
        std::string block = ciphertext.substr(i, 8);
        blocks.push_back(block);
    }

    //same as encrypt: turn each block into a 64-char binary string and a hex string
    std::vector<std::array<char, 8>> blockCharArrays;
    std::vector<std::string> blockBinary; // one 64-char '0'/'1' string per block
    std::vector<std::string> blockHex;    // one 16-hex-digit string per block
    for (auto& block : blocks) {
        std::array<char, 8> chars{};
        std::string binaryStr;
        std::string hexStr;
        for (int i = 0; i < 8; i++) {
            chars[i] = block[i];
            binaryStr += std::bitset<8>(static_cast<unsigned char>(block[i])).to_string();
            std::stringstream ss;
            ss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(static_cast<unsigned char>(block[i]));
            hexStr += ss.str();
        }
        blockCharArrays.push_back(chars);
        blockBinary.push_back(binaryStr);
        blockHex.push_back(hexStr);
    }

    //key processing -- identical to encrypt(), key is already exactly 8 bytes
    std::vector<std::string> keyBlocks;
    keyBlocks.push_back(key);
    std::vector<std::array<char, 8>> keyCharArrays;
    std::vector<std::string> keyBinary; // one 64-char '0'/'1' string
    std::vector<std::string> keyHex;    // one 16-hex-digit string
    for (auto& block : keyBlocks) {
        std::array<char, 8> chars{};
        std::string binaryStr;
        std::string hexStr;
        for (int i = 0; i < 8; i++) {
            chars[i] = block[i];
            binaryStr += std::bitset<8>(static_cast<unsigned char>(block[i])).to_string();
            std::stringstream ss;
            ss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(static_cast<unsigned char>(block[i]));
            hexStr += ss.str();
        }
        keyCharArrays.push_back(chars);
        keyBinary.push_back(binaryStr);
        keyHex.push_back(hexStr);
    }

    //Round key processing -- same PC-1 / shift schedule / PC-2 as encrypt()
    const int PC1[56] = {
        57, 49, 41, 33, 25, 17,  9,
         1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
         7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4
    };
    std::string binaryPlaceholder;
    for (auto& keyBinarys : keyBinary) {
        for (int i = 0; i < 56; i++) {
            binaryPlaceholder += keyBinarys[PC1[i] - 1];
        }
    }
    std::string K_i_L;
    std::string K_i_R;
    for (int i = 0; i < 56; i++) {
        if (i < 28) {
            K_i_L += binaryPlaceholder[i];
        }
        else {
            K_i_R += binaryPlaceholder[i];
        }
    }

    const int SHIFT_SCHEDULE[16] = {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    const int PC2[48] = {
        14, 17, 11, 24,  1,  5,
         3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8,
        16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };

    std::vector<std::string> K_i_rounds;
    for (int i = 0; i < 16; i++) {
        std::string K_i;
        std::string K_holder1;
        std::string K_holder2;

        for (int j = 0; j < 28; j++) {
            if (j + SHIFT_SCHEDULE[i] < 28) {
                K_holder1 += K_i_L[j + SHIFT_SCHEDULE[i]];
                K_holder2 += K_i_R[j + SHIFT_SCHEDULE[i]];
            }
            else {
                K_holder1 += K_i_L[(j + SHIFT_SCHEDULE[i]) % 28];
                K_holder2 += K_i_R[(j + SHIFT_SCHEDULE[i]) % 28];
            }
        }
        K_i += K_holder1;
        K_i += K_holder2;
        std::string K_i_holder;
        for (int i2 = 0; i2 < 48; i2++) {
            K_i_holder += K_i[PC2[i2] - 1];
        }
        K_i_rounds.push_back(K_i_holder);

        //shift C/D forward for the next round, same as encrypt() does implicitly
        //by re-deriving from binaryPlaceholder each time -- here we advance
        //K_i_L/K_i_R so round i+1 shifts from round i's position.
        //im using this to fix the error of non-shifting c0/d0 from before.
        K_i_L = K_holder1;
        K_i_R = K_holder2;
    }

    //*** decryption uses the round keys in REVERSE order ***
    std::vector<std::string> K_i_rounds_reversed(K_i_rounds.rbegin(), K_i_rounds.rend());

    //IP applied to ciphertext blocks (same table as encrypt)
    const int IP[64] = {
        58, 50, 42, 34, 26, 18, 10,  2,
        60, 52, 44, 36, 28, 20, 12,  4,
        62, 54, 46, 38, 30, 22, 14,  6,
        64, 56, 48, 40, 32, 24, 16,  8,
        57, 49, 41, 33, 25, 17,  9,  1,
        59, 51, 43, 35, 27, 19, 11,  3,
        61, 53, 45, 37, 29, 21, 13,  5,
        63, 55, 47, 39, 31, 23, 15,  7
    };
    std::vector<std::string> BBPHIP_ciphertext_in;
    for (auto& blockBinarys : blockBinary) {
        std::string bbPlaceholder;
        for (int i = 0; i < 64; i++) {
            bbPlaceholder += blockBinarys[IP[i] - 1];
        }
        BBPHIP_ciphertext_in.push_back(bbPlaceholder);
    }

    const int FP[64] = {
        40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25
    };

    const int E_TABLE[48] = {
        32,  1,  2,  3,  4,  5,
         4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1
    };

    const int P_TABLE[32] = {
        16,  7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26,  5, 18, 31, 10,
         2,  8, 24, 14, 32, 27,  3,  9,
        19, 13, 30,  6, 22, 11,  4, 25
    };

    const int S_BOXES[8][4][16] = {
        { // S1
            {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
            { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
            { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
            {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
        },
        { // S2
            {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
            { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
            { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
            {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
        },
        { // S3
            {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
            {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
            {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
            { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
        },
        { // S4
            { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
            {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
            {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
            { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
        },
        { // S5
            { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
            {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
            { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
            {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
        },
        { // S6
            {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
            {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
            { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
            { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
        },
        { // S7
            { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
            {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
            { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
            { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
        },
        { // S8
            {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
            { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
            { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
            { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
        }
    };

    //run the Feistel network on each block, using K_i_rounds_reversed instead of K_i_rounds
    std::vector<std::string> BBPHIP_plaintext_out;

    for (auto& block : BBPHIP_ciphertext_in) {
        std::string L_i;
        std::string R_i;
        for (int i = 0; i < 64; i++) {
            if (i < 32) {
                L_i += block[i];
            }
            else {
                R_i += block[i];
            }
        }

        for (auto& K_i_round : K_i_rounds_reversed) {
            std::string new_L = R_i;

            std::string E_table_R;
            for (int i = 0; i < (int)R_i.size(); i++) {
                E_table_R += R_i[E_TABLE[i] - 1];
            }

            std::bitset<48> ETRbits(E_table_R);
            std::bitset<48> KIRbits(K_i_round);
            unsigned long long ETRval = ETRbits.to_ullong();
            unsigned long long KIRval = KIRbits.to_ullong();
            unsigned long long new_R_xor = ETRval ^ KIRval;
            std::string new_R = std::bitset<48>(new_R_xor).to_string();

            std::string SboxR;
            int scount = 0;
            for (int i = 0; i < 48; i += 6) {
                std::string bb1;
                bb1 += new_R[i];
                bb1 += new_R[i + 5];
                std::string bb2;
                bb2 += new_R[i + 1];
                bb2 += new_R[i + 2];
                bb2 += new_R[i + 3];
                bb2 += new_R[i + 4];
                std::bitset<2> bits1(bb1);
                std::bitset<4> bits2(bb2);
                unsigned long valbit1 = bits1.to_ulong();
                unsigned long valbit2 = bits2.to_ulong();
                int selection = S_BOXES[scount][valbit1][valbit2];
                SboxR += std::bitset<4>(selection).to_string();
                scount++;
            }

            std::string frustration;
            for (int i = 0; i < 32; i++) {
                frustration += SboxR[P_TABLE[i] - 1];
            }

            std::bitset<32> LXORbits(L_i);
            std::bitset<32> frustratingBITS(frustration);
            unsigned long LXORval = LXORbits.to_ulong();
            unsigned long frustratingVAL = frustratingBITS.to_ulong();
            unsigned long LXRfrust = LXORval ^ frustratingVAL;
            std::string GOD = std::bitset<32>(LXRfrust).to_string();
            R_i = GOD;
            L_i = new_L;
        }

        std::string swapR;
        std::string swapL;
        for (int i = 0; i < 32; i++) {
            swapR += L_i[i];
            swapL += R_i[i];
        }
        std::string buildPRE = swapL + swapR;
        std::string preplain;
        for (int i = 0; i < 64; i++) {
            preplain += buildPRE[FP[i] - 1];
        }

        BBPHIP_plaintext_out.push_back(preplain);
    }

    std::string binary;
    for (auto& blk : BBPHIP_plaintext_out) {
        binary += blk;
    }

    std::string text;
    for (size_t i = 0; i < binary.size(); i += 8) {
        std::string eightBits = binary.substr(i, 8);
        unsigned long value = std::bitset<8>(eightBits).to_ulong();
        text += static_cast<char>(value);
    }

    //strip the PKCS#7-style padding that encrypt() added: the last byte's
    //value tells us how many padding bytes were appended (1-8).
    if (!text.empty()) {
        unsigned char padLen = static_cast<unsigned char>(text.back());
        if (padLen >= 1 && padLen <= 8 && padLen <= text.size()) {
            text.erase(text.size() - padLen);
        }
    }

    return text;
}



//std::string DESCipher::decrypt(const std::string& ciphertext, const std::string& key) const {
//    std::cout << "[DESCipher::decrypt] TODO not yet implemented -- returning ciphertext unchanged.\n";
//
//    return ciphertext;
//}
