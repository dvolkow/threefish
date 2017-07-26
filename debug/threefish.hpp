#ifndef THREEFISH_HPP 
#define THREEFISH_HPP 

#include <cstdint>
#include <utility>

namespace threefish 
{
    using std::size_t;

    static const uint64_t C240 = 0x1BD11BDAA9FC1A22ULL;

    // rotation constants for threefish
    template<int> 
    struct rotation_table; 

    typedef rotation_table<256> r256;
    typedef rotation_table<512> r512;
    typedef rotation_table<1024> r1024;

    // permutation constants
    template<int> struct inverstions_table;

    typedef inverstions_table<256> i256;
    typedef inverstions_table<512> i512;
    typedef inverstions_table<1024> i1024;

    inline uint64_t rol(const uint64_t n, const uint8_t shift)
    {
        return (n << shift) | (n >> (64 - shift));
    }

    inline uint64_t ror(const uint64_t n, const uint8_t shift)
    {
        return (n << (64 - shift)) | (n >> shift);
    }

    inline void mix(uint64_t x0, uint64_t x1, uint64_t & y0, uint64_t & y1, uint8_t r)
    {
        y0 = x0 + x1;
        y1 = rol(x1, r) ^ y0;
    }

    inline void demix(uint64_t y0, uint64_t y1, uint64_t & x0, uint64_t & x1, uint8_t r)
    {
        x1 = ror(y0 ^ y1, r);
        x0 = y0 - x1;
    }

    void encrypted_round_mix(const uint8_t nw, uint64_t * v, const uint8_t * r, const uint8_t * p)
    {
        for (uint8_t i = 0; i < nw; i += 2)
            mix(v[p[i]], v[p[i + 1]], v[p[i]], v[p[i + 1]], r[i / 2]);
    }

    void decrypted_round_mix(const uint8_t nw, uint64_t * v, const uint8_t * r, const uint8_t * p)
    {
        for (uint8_t i = 0; i < nw; i += 2)
            demix(v[p[i]], v[p[i + 1]], v[p[i]], v[p[i + 1]], r[i / 2]);
    }

    void threefish_exp(const uint8_t nw, const uint8_t nr, uint64_t * key, uint64_t * tweak, uint64_t ** subkeys)
    {
        uint64_t xkey[nw + 1];
        uint64_t xtweak[3] = {tweak[0], tweak[1], tweak[0] ^ tweak[1]};

        xkey[nw] = C240;
        for (uint8_t i = 0; i < nw; ++i)
            xkey[i] = key[i], xkey[nw] ^= key[i];

        for (uint8_t i = 0; i < nr / 4 + 1; ++i)
        {
            for (uint8_t j = 0; j < nw; ++j)
                subkeys[i][j] = xkey[(i + j) % (nw + 1)];

            subkeys[i][nw - 3] += xtweak[i % 3];
            subkeys[i][nw - 2] += xtweak[(i + 1) % 3];
            subkeys[i][nw - 1] += i;
        }
    }

    void encrypt_generic(const uint8_t nw, const uint8_t nr, const uint8_t ** rot, 
                         const uint8_t ** p, uint8_t * key, uint64_t * tweak,
                         uint64_t * plaintext, uint64_t * ciphertext)
    {
        uint64_t subkeys[nr/4 + 1][nw];
        threefish_exp(nw, nr, key, tweak, &subkeys);

        uint64_t v[nw];

	    for (uint8_t i = 0; i < nw; ++i) 
		    v[i] = plaintext[i];
        
        for (uint8_t n = 0; n < nr; n += 8) 
        {
		    for (uint8_t w = 0; w < nw; ++w) 
			    v[w] += subkeys[n / 4][w];
		
            encrypted_round_mix(nw, v, rot[(n + 0) % 8], p[0]);
            encrypted_round_mix(nw, v, rot[(n + 1) % 8], p[1]);
            encrypted_round_mix(nw, v, rot[(n + 2) % 8], p[2]);
            encrypted_round_mix(nw, v, rot[(n + 3) % 8], p[3]);

            for (uint8_t w = 0; w < nw; ++w) 
                v[w] += subkeys[n / 4 + 1][w];
		    
            encrypted_round_mix(nw, v, rot[(n + 4) % 8], p[0]);
            encrypted_round_mix(nw, v, rot[(n + 5) % 8], p[1]);
            encrypted_round_mix(nw, v, rot[(n + 6) % 8], p[2]);
            encrypted_round_mix(nw, v, rot[(n + 7) % 8], p[3]);
        }

        for (unsigned w = 0; w < nw; ++w) 
            ciphertext[w] = v[w] + subkeys[nr/4][w];
    }

    void decrypt_generic(const uint8_t nw, const uint8_t nr, const uint8_t ** rot, 
                         const uint8_t ** p, uint8_t * key, uint64_t * tweak,
                         uint64_t * ciphertext, uint64_t * plaintext)
    {
        uint64_t subkeys[nr/4 + 1][nw];
        threefish_exp(nw, nr, key, tweak, &subkeys);

        uint64_t v[nw];

        for (uint8_t i = 0; i < nw; ++i) 
            v[i] = ciphertext[i] - subkeys[nr / 4][i];
        
        for (uint8_t n = nr - 8; n != 0; n -= 8) 
        {
            decrypted_round_mix(nw, v, rot[(n + 7) % 8], p[3]);
            decrypted_round_mix(nw, v, rot[(n + 6) % 8], p[2]);
            decrypted_round_mix(nw, v, rot[(n + 5) % 8], p[1]);
            decrypted_round_mix(nw, v, rot[(n + 4) % 8], p[0]);

            for (uint8_t w = 0; w < nw; ++w) 
                v[w] -= subkeys[n / 4 + 1][w];

            decrypted_round_mix(nw, v, rot[(n + 3) % 8], p[3]);
            decrypted_round_mix(nw, v, rot[(n + 2) % 8], p[2]);
            decrypted_round_mix(nw, v, rot[(n + 1) % 8], p[1]);
            decrypted_round_mix(nw, v, rot[(n + 0) % 8], p[0]);

            for (uint8_t w = 0; w < nw; ++w) 
                v[w] -= subkeys[n / 4][w];
        }

        for (uint8_t w = 0; w < nw; ++w) 
            plaintext[w] = v[w];
    }

    template<int>
    class TFish;

    template<>
    class TFish<256> 
    {
    };

    template<>
        struct rotation_table<256> 
        {
            static constexpr uint8_t arr[8][2] = {  {14, 16}, {52, 57}, {23, 40}, { 5, 37},
                                                    {25, 33}, {46, 12}, {58, 22}, {32, 32}
            };
        };

    template<>
        struct rotation_table<512>
        {
            static constexpr uint8_t arr[8][4] = {  {46, 36, 19, 37}, 	{33, 27, 14, 42},
                                                 	{17, 49, 36, 39},	{44,  9, 54, 56},
                                                    {39, 30, 34, 24}, 	{13, 50, 10, 17},
                                                	{25, 29, 39, 43}, 	{ 8, 35, 56, 22}
            };
        };

    template<>
        struct rotation_table<1024>
        {
            static constexpr uint8_t arr[8][8] = {  {24, 13,  8, 47,  8, 17, 22, 37},
                                                	{38, 19, 10, 55, 49, 18, 23, 52},
                                                	{33,  4, 51, 13, 34, 41, 59, 17},
                                                	{ 5, 20, 48, 41, 47, 28, 16, 25},
                                                	{41,  9, 37, 31, 12, 47, 44, 30},
                                                	{16, 34, 56, 51,  4, 53, 42, 41},
                                                	{31, 44, 47, 46, 19, 42, 44, 25},
                                                	{ 9, 48, 35, 52, 23, 31, 37, 20}
            };
        };

    template<>
        struct inverstions_table<256>
        {
            static constexpr uint8_t arr[4][4] = {  {0, 1, 2, 3},	{0, 3, 2, 1},
                                                	{0, 1, 2, 3},   {0, 3, 2, 1}
            };
        };

    template<>
        struct inverstions_table<512>
        {
            static constexpr uint8_t arr[4][8] = {  {0, 1, 2, 3, 4, 5, 6, 7},
                                                	{2, 1, 4, 7, 6, 5, 0, 3},
                                                	{4, 1, 6, 3, 0, 5, 2, 7},
                                                	{6, 1, 0, 7, 2, 5, 4, 3}
            };
        };

    template<>
        struct inverstions_table<1024>
        {
            static constexpr uint8_t arr[4][16] = { {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
                                                	{0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1},
                                                	{0, 7, 2, 5, 4, 3, 6, 1, 12, 15, 14, 13, 8, 11, 10, 9},
                                                	{0, 15, 2, 11, 6, 13, 4, 9, 14, 1, 8, 5, 10, 3, 12, 7}
            };
        };

} // threefish
#endif
