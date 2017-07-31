# threefish
My implementation ThreeFish-crypt algo

## Install
Run ```install.sh``` as root/sudo.

## Types and interface
```cpp

namespace threefish
{
    template <uint8_t SIZE_BLOCK> // SIZE_BLOCK in 64-bit words
    class Cryptor
    {
    public:
        void encrypt(const size_t count_blocks, uint64_t * source, uint64_t * destination);
        void decrypt(const size_t count_blocks, uint64_t * source, uint64_t * destination);
    };
}
```

## Usage
```cpp
#include <my_dev/threefish>

//  You can init cryptor class by std::string or uint64_t array.
//  Cryptor is template class: can be instance of <4>, <8> or <16> for 256-, 512- or 1024 bits length key/blocks:
threefish::Cryptor<4> c_256("password");
threefish::Cryptor<8> c_512(""); // password is empty string

uint64_t key[16] = {0, 1, 2, 3, 4}; // key may be define as array of uint64_t
threefish::Cryptor<16> c_1024(&key[0]);

//  Encrypt text
uint64_t plaintext[SIZE_TXT] = { /* your text */ }; 
uint64_t ciphertext[SIZE_TXT] = { /* place for ciphertext */ };

c_1024.encrypt(SIZE_TXT / 16, &plaintext[0], &ciphertext[0]); // 16 because is SIZE_BLOCK for current example cryptor (1024 bit)

//  Decrypt text
c_1024.decrypt(SIZE_TXT / 16, &ciphertext[0], &plaintext[0]); 

```
