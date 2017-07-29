#include "../debug/threefish.hpp"
#include <iostream>
#include <fstream>
#include <cassert>

int main()
{

    uint64_t key[16] = {0};
	uint64_t plaintext[16] = {0};
    threefish::base<16> enc(&key[0]);
    enc.encrypt_block(&plaintext[0]);
    enc.decrypt_block(&enc.ciphertext_[0]);


    std::ofstream plaintext_file;
    plaintext_file.open("plaintext.txt", std::ios::binary);
    std::ofstream cypertext_file;
    cypertext_file.open("cypertext.txt", std::ios::binary);
    std::ofstream decrypt_file;
    decrypt_file.open("decrypt.txt", std::ios::binary);

    for (uint8_t i = 0; i < 16; ++i)
    {
        plaintext_file << plaintext[i];
    }

    for (uint8_t i = 0; i < 16; ++i)
    {
        cypertext_file << enc.ciphertext_[i];
        decrypt_file << enc.plaintext_[i];
    }
//    std::cout << static_cast<char>()
 //   std::cout << static_cast<int>(threefish::rotation_table<16>::arr[2][1]) << " " << a << "\n";
    plaintext_file.close(), cypertext_file.close(), decrypt_file.close();
}
