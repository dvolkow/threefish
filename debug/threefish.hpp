#ifndef THREEFISH_HPP 
#define THREEFISH_HPP 

#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

namespace threefish 
{
    using std::size_t;
    using std::vector;
    // rotation constants for threefish:
    template<uint8_t> struct rotation_table; 
    // permutation constants:
    template<uint8_t> struct inverstions_table;


    template <uint8_t SIZE_BLOCK>
    class Cryptor 
    {
        typedef rotation_table<SIZE_BLOCK> r_type;
        typedef inverstions_table<SIZE_BLOCK> inv_type;

    public:
        Cryptor(uint64_t * key) 
            : plaintext_(SIZE_BLOCK), ciphertext_(SIZE_BLOCK), subkeys_(), tweak_(), nw_(SIZE_BLOCK), nr_(SIZE_BLOCK < 16 ? 72 : 80) 
            {
                keys_expand(key);
            } 

        void encrypt(const size_t count_blocks, uint64_t * source, uint64_t * dest)
        {
            for (size_t i = 0; i < count_blocks; ++i)
            {
                encrypt_block(source + i * SIZE_BLOCK);
                std::memcpy(dest + i * SIZE_BLOCK, &ciphertext_[0], ciphertext_.size() * sizeof(ciphertext_[0]));
            }
        }

        void decrypt(const size_t count_blocks, uint64_t * source, uint64_t * dest)
        {
            for (size_t i = 0; i < count_blocks; ++i)
            {
                decrypt_block(source + i * SIZE_BLOCK);
                std::memcpy(dest + i * SIZE_BLOCK, &plaintext_[0], plaintext_.size() * sizeof(plaintext_[0]));
            }
        }

    private:
        void keys_expand(uint64_t * key);
        void encrypt_block(uint64_t * block);
        void decrypt_block(uint64_t * block);

    private:
        vector<uint64_t> plaintext_;
        vector<uint64_t> ciphertext_;
        vector<vector<uint64_t>> subkeys_;

        uint64_t tweak_[3]; 
        uint8_t nw_, nr_;
        r_type rot_;
        inv_type inv_;
    };



    static const uint64_t C240 = 0x1BD11BDAA9FC1A22ULL;

    // byte rotation left-right
    inline uint64_t rol(const uint64_t n, const uint8_t shift)
    {
        return (n << shift) | (n >> (64 - shift));
    }

    inline uint64_t ror(const uint64_t n, const uint8_t shift)
    {
        return (n << (64 - shift)) | (n >> shift);
    }

    // MIX function
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
        const uint8_t di = 2U;
        for (uint8_t i = 0; i < nw; i += di)
            mix(v[p[i]], v[p[i + 1]], v[p[i]], v[p[i + 1]], r[i / di]);
    }

    void decrypted_round_mix(const uint8_t nw, uint64_t * v, const uint8_t * r, const uint8_t * p)
    {
        const uint8_t di = 2U;
        for (uint8_t i = 0; i < nw; i += di)
            demix(v[p[i]], v[p[i + 1]], v[p[i]], v[p[i + 1]], r[i / di]);
    }


    template<uint8_t SIZE_BLOCK>
    void Cryptor<SIZE_BLOCK>::keys_expand(uint64_t * key)
    {
        subkeys_ = vector<vector<uint64_t>>(nr_ / 4 + 1, vector<uint64_t>(nw_));
        
        vector<uint64_t> xkey(nw_ + 1);
        xkey[nw_] = C240;

        for (uint8_t i = 0; i < nw_; ++i)
            xkey[i] = key[i], xkey[nw_] ^= key[i];

        for (uint8_t i = 0; i < subkeys_.size(); ++i)
        {
            for (uint8_t j = 0; j < nw_; ++j)
                subkeys_[i][j] = xkey[(i + j) % (nw_ + 1)];

            subkeys_[i][nw_ - 3] += tweak_[i % 3];
            subkeys_[i][nw_ - 2] += tweak_[(i + 1) % 3];
            subkeys_[i][nw_ - 1] += i;
        }
    }

    template<uint8_t SIZE_BLOCK>
    void Cryptor<SIZE_BLOCK>::encrypt_block(uint64_t * block)
    {
        vector<uint64_t> v(nw_);

	    for (uint8_t i = 0; i < nw_; ++i) 
		    v[i] = block[i];
        
        for (uint8_t n = 0; n < nr_; n += 8U) 
        {
		    for (uint8_t w = 0; w < nw_; ++w) 
			    v[w] += subkeys_[n / 4][w];
		
            encrypted_round_mix(nw_, &v[0], rot_.arr[(n + 0) % 8], inv_.arr[0]);
            encrypted_round_mix(nw_, &v[0], rot_.arr[(n + 1) % 8], inv_.arr[1]);
            encrypted_round_mix(nw_, &v[0], rot_.arr[(n + 2) % 8], inv_.arr[2]);
            encrypted_round_mix(nw_, &v[0], rot_.arr[(n + 3) % 8], inv_.arr[3]);

            for (uint8_t w = 0; w < nw_; ++w) 
                v[w] += subkeys_[n / 4 + 1][w];
		    
            encrypted_round_mix(nw_, &v[0], rot_.arr[(n + 4) % 8], inv_.arr[0]);
            encrypted_round_mix(nw_, &v[0], rot_.arr[(n + 5) % 8], inv_.arr[1]);
            encrypted_round_mix(nw_, &v[0], rot_.arr[(n + 6) % 8], inv_.arr[2]);
            encrypted_round_mix(nw_, &v[0], rot_.arr[(n + 7) % 8], inv_.arr[3]);
        }

        for (uint8_t w = 0; w < nw_; ++w) 
            ciphertext_[w] = v[w] + subkeys_[nr_ / 4][w];
    }

    template<uint8_t SIZE_BLOCK>
    void Cryptor<SIZE_BLOCK>::decrypt_block(uint64_t * block)
    {
        vector<uint64_t> v(nw_);

        for (uint8_t i = 0; i < nw_; ++i) 
            v[i] = block[i] - subkeys_[nr_ / 4][i];
        
        for (uint8_t n = nr_; n != 0; ) 
        {
            n -= 8U;

            decrypted_round_mix(nw_, &v[0], rot_.arr[(n + 7) % 8], inv_.arr[3]);
            decrypted_round_mix(nw_, &v[0], rot_.arr[(n + 6) % 8], inv_.arr[2]);
            decrypted_round_mix(nw_, &v[0], rot_.arr[(n + 5) % 8], inv_.arr[1]);
            decrypted_round_mix(nw_, &v[0], rot_.arr[(n + 4) % 8], inv_.arr[0]);

            for (uint8_t w = 0; w < nw_; ++w) 
                v[w] -= subkeys_[n / 4 + 1][w];

            decrypted_round_mix(nw_, &v[0], rot_.arr[(n + 3) % 8], inv_.arr[3]);
            decrypted_round_mix(nw_, &v[0], rot_.arr[(n + 2) % 8], inv_.arr[2]);
            decrypted_round_mix(nw_, &v[0], rot_.arr[(n + 1) % 8], inv_.arr[1]);
            decrypted_round_mix(nw_, &v[0], rot_.arr[(n + 0) % 8], inv_.arr[0]);

            for (uint8_t w = 0; w < nw_; ++w) 
                v[w] -= subkeys_[n / 4][w];
        }

        for (uint8_t w = 0; w < nw_; ++w) 
            plaintext_[w] = v[w];
    }

    template<>
        struct rotation_table<4> 
        {
            static constexpr uint8_t arr[8][2] = {  {14, 16}, {52, 57}, {23, 40}, { 5, 37},
                                                    {25, 33}, {46, 12}, {58, 22}, {32, 32}
            };
        };

    template<>
        struct rotation_table<8>
        {
            static constexpr uint8_t arr[8][4] = {  {46, 36, 19, 37}, 	{33, 27, 14, 42},
                                                    {17, 49, 36, 39},	{44,  9, 54, 56},
                                                    {39, 30, 34, 24}, 	{13, 50, 10, 17},
                                                    {25, 29, 39, 43}, 	{ 8, 35, 56, 22}
            };
        };

    template<>
        struct rotation_table<16>
        {
            uint8_t arr[8][8] = {   {24, 13,  8, 47,  8, 17, 22, 37},
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
        struct inverstions_table<4>
        {
            static constexpr uint8_t arr[4][4] = {  {0, 1, 2, 3},	{0, 3, 2, 1},
                                                    {0, 1, 2, 3},   {0, 3, 2, 1}
            };
        };

    template<>
        struct inverstions_table<8>
        {
            static constexpr uint8_t arr[4][8] = {  {0, 1, 2, 3, 4, 5, 6, 7},
                                                    {2, 1, 4, 7, 6, 5, 0, 3},
                                                    {4, 1, 6, 3, 0, 5, 2, 7},
                                                    {6, 1, 0, 7, 2, 5, 4, 3}
            };
        };

    template<>
        struct inverstions_table<16>
        {
            uint8_t arr[4][16] = { {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
                                   {0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1},
                                   {0, 7, 2, 5, 4, 3, 6, 1, 12, 15, 14, 13, 8, 11, 10, 9},
                                   {0, 15, 2, 11, 6, 13, 4, 9, 14, 1, 8, 5, 10, 3, 12, 7}
            };
        };

} // threefish
#endif
