#include "../debug/threefish.hpp"
#include <iostream>
#include <fstream>
#include <cassert>

int main()
{

    uint64_t key[16] = {0};
	uint64_t plaintext[32] = {0};
	uint64_t cypertext[32] = {0};
	uint64_t decrypt[32] = {0};

    //threefish::Cryptor<16> enc(&key[0]);
    threefish::Cryptor<16> enc("password");
    enc.encrypt(2, &plaintext[0], &cypertext[0]);
    enc.decrypt(2, &cypertext[0], &decrypt[0]);


    std::ofstream plaintext_file;
    plaintext_file.open("plaintext.txt", std::ios::binary);
    std::ofstream cypertext_file;
    cypertext_file.open("cypertext.txt", std::ios::binary);
    std::ofstream decrypt_file;
    decrypt_file.open("decrypt.txt", std::ios::binary);

    for (uint8_t i = 0; i < 32; ++i)
    {
        plaintext_file << plaintext[i];
    }

    for (uint8_t i = 0; i < 32; ++i)
    {
        cypertext_file << cypertext[i];
        decrypt_file << decrypt[i];
    }
//    std::cout << static_cast<char>()
 //   std::cout << static_cast<int>(threefish::rotation_table<16>::arr[2][1]) << " " << a << "\n";
    plaintext_file.close(), cypertext_file.close(), decrypt_file.close();
}
