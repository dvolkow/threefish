#include "../debug/threefish.hpp"
#include <iostream>

int main()
{
    uint8_t a = threefish::rotation_table<256>::arr[1][0];
    std::cout << static_cast<int>(threefish::rotation_table<256>::arr[2][1]) << " " << a << "\n";
}
