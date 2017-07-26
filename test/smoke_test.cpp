#include "../debug/threefish.hpp"
#include <iostream>

int main()
{

    uint8_t key[128] = "passwordpasswordpasswordpassword";
	uint8_t plaintext[128] = "plaintxtplaintxtplaintxtplaintxt";
    threefish::base<16> enc(reinterpret_cast<uint64_t *>(&key));
    enc.decrypt_block(reinterpret_cast<uint64_t *>(&plaintext));

//    uint8_t a = threefish::rotation_table<16>::arr[1][0];
 //   std::cout << static_cast<int>(threefish::rotation_table<16>::arr[2][1]) << " " << a << "\n";
}
