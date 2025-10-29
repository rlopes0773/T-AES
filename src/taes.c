// T-AES implementation using standard C and lookup tables
#include "../include/taes.h"
#include <string.h>
#include <stdio.h>


// AES S-box (forward substitution)
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Inverse S-box 
static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// AES round constants for key expansion
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Debug helper function to print state
static void print_state(const uint8_t *state) {
    for (int i = 0; i < 16; i++) {
        printf("%02x ", state[i]);
    }
    printf("\n");
}

// Key expansion helper: SubWord operation (apply S-box to each byte of word)
// Word format: 0xAABBCCDD where AA is byte 0, BB is byte 1, etc.
static uint32_t sub_word(uint32_t word) {
    uint8_t b0 = (word >> 24) & 0xFF;
    uint8_t b1 = (word >> 16) & 0xFF;
    uint8_t b2 = (word >> 8) & 0xFF;
    uint8_t b3 = word & 0xFF;
    return ((uint32_t)sbox[b0] << 24) | ((uint32_t)sbox[b1] << 16) |
           ((uint32_t)sbox[b2] << 8) | (uint32_t)sbox[b3];
}

// Key expansion helper: RotWord operation (rotate word left by 1 byte)
static uint32_t rot_word(uint32_t word) {
    return (word << 8) | (word >> 24);
}

// AES key expansion - generates round keys from master key
static void key_expansion(const uint8_t *key, uint8_t *round_keys, int key_size, int num_rounds) {
    int nk = key_size / 4;  // Number of 32-bit words in key (4, 6, or 8)
    int nr = num_rounds;     // Number of rounds
    uint32_t w[60];  // Maximum size: 4 * (14 + 1) = 60 words for AES-256

    // Copy the key into the first Nk words of the expanded key
    // AES uses big-endian word representation
    for (int i = 0; i < nk; i++) {
        w[i] = ((uint32_t)key[4*i] << 24) | ((uint32_t)key[4*i+1] << 16) |
               ((uint32_t)key[4*i+2] << 8) | ((uint32_t)key[4*i+3]);
    }

    // Generate the rest of the round keys
    for (int i = nk; i < 4 * (nr + 1); i++) {
        uint32_t temp = w[i-1];

        if (i % nk == 0) {
            temp = sub_word(rot_word(temp)) ^ ((uint32_t)rcon[i/nk] << 24);
        } else if (nk > 6 && i % nk == 4) {
            temp = sub_word(temp);
        }

        w[i] = w[i-nk] ^ temp;
    }

    // Convert words to bytes in round_keys array
    for (int i = 0; i < 4 * (nr + 1); i++) {
        round_keys[4*i]     = (w[i] >> 24) & 0xFF;
        round_keys[4*i + 1] = (w[i] >> 16) & 0xFF;
        round_keys[4*i + 2] = (w[i] >> 8) & 0xFF;
        round_keys[4*i + 3] = w[i] & 0xFF;
    }

    //Print round keys for debugging

    // printf("Round Keys:\n");
    // for (int i = 0; i < 4 * (nr + 1); i++) {
    //     printf("W[%2d]: %08x\n", i, w[i]);
    // }
}

static void add_round_key(const taes_ctx *ctx, const uint8_t *state, uint8_t *output, int round) {
    // XOR state with round key
    int offset = round * 16;
    for (int i = 0; i < 16; i++) {
        output[i] = state[i] ^ ctx->round_keys[offset + i];
    }

}

uint8_t gmul2(uint8_t a) {
    uint8_t hi_bit = a & 0x80;  // Check if high bit is set
    a <<= 1;                     // Multiply by 2 (left shift)
    if (hi_bit) {
        a ^= 0x1B;  // XOR with irreducible polynomial if overflow
    }
    return a;
}

uint8_t gmul3(uint8_t a) {
    return gmul2(a) ^ a;  // 3*a = 2*a + a in GF(2^8)
}

static void mix_columns(uint8_t *state) {
    for (int col = 0; col < 4; col++) {
        uint8_t s0 = state[col * 4];
        uint8_t s1 = state[col * 4 + 1];
        uint8_t s2 = state[col * 4 + 2];
        uint8_t s3 = state[col * 4 + 3];

        state[col * 4]      = gmul2(s0) ^ gmul3(s1) ^ s2 ^ s3;
        state[col * 4 + 1]  = s0 ^ gmul2(s1) ^ gmul3(s2) ^ s3;
        state[col * 4 + 2]  = s0 ^ s1 ^ gmul2(s2) ^ gmul3(s3);
        state[col * 4 + 3] = gmul3(s0) ^ s1 ^ s2 ^ gmul2(s3);
    }
}

  // Inverse MixColumns transformation for decryption
  static void inv_mix_columns(uint8_t *state) {
      for (int col = 0; col < 4; col++) {
          uint8_t s0 = state[col * 4];
          uint8_t s1 = state[col * 4 + 1];
          uint8_t s2 = state[col * 4 + 2];
          uint8_t s3 = state[col * 4 + 3];

        //   state[col]      = gmul14(s0) ^ gmul11(s1) ^ gmul13(s2) ^ gmul9(s3);
        //   state[col + 4]  = gmul9(s0) ^ gmul14(s1) ^ gmul11(s2) ^ gmul13(s3);
        //   state[col + 8]  = gmul13(s0) ^ gmul9(s1) ^ gmul14(s2) ^ gmul11(s3);
        //   state[col + 12] = gmul11(s0) ^ gmul13(s1) ^ gmul9(s2) ^ gmul14(s3);
      }
}

static void sub_bytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

static void inv_sub_bytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = inv_sbox[state[i]];
    }
}

static void shift_rows(uint8_t *state) {
    uint8_t temp;

    // Row 1: shift left by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Row 2: shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Row 3: shift left by 3
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

static void inv_shift_rows(uint8_t *state) {
    uint8_t temp;

    // Row 1: shift right by 1
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    // Row 2: shift right by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Row 3: shift right by 3
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}


// Initialize T-AES context
int taes_init(taes_ctx *ctx, const uint8_t *key, int key_size, const uint8_t *tweak) {
    if (!ctx || !key) {
        return -1;
    }

    // Validate key size
    if (key_size != 16 && key_size != 24 && key_size != 32) {
        return -1;
    }

    ctx->key_size = key_size;

    // Set number of rounds based on key size
    switch (key_size) {
        case 16: ctx->num_rounds = 10; ctx->tweak_round = 5; break;
        case 24: ctx->num_rounds = 12; ctx->tweak_round = 6; break;
        case 32: ctx->num_rounds = 14; ctx->tweak_round = 7; break;
    }

    key_expansion(key, ctx->round_keys, key_size, ctx->num_rounds);
    
    // Store tweak
    if (tweak) {
        memcpy(ctx->tweak, tweak, TWEAK_SIZE);
    } else {
        memset(ctx->tweak, 0, TWEAK_SIZE);
    }

    return 0;
}

// Encrypt a single block
void taes_encrypt_block(const taes_ctx *ctx, const uint8_t *plaintext, uint8_t *ciphertext) {
    uint8_t round = 0;
    // TODO: Implement T-AES encryption
    // 1. Initial AddRoundKey
    printf("round [%d].input ", round);
    print_state(plaintext);

    printf("round [%d].k_sch ", round);
    print_state(ctx->round_keys[0]);
    
    add_round_key(ctx, plaintext, ciphertext, round);
    
    // 2. Rounds 1 to (num_rounds - 1):
    for (round = 1; round < ctx->num_rounds; round++) {
        printf("round [%d].start ", round);
        print_state(ciphertext);
        
        //    - SubBytes
        sub_bytes(ciphertext);
        printf("round [%d].s_box ", round);
        print_state(ciphertext);

        //    - ShiftRows
        shift_rows(ciphertext);
        printf("round [%d].s_row ", round);
        print_state(ciphertext);

        //    - MixColumns
        mix_columns(ciphertext);
        printf("round [%d].m_col ", round);
        print_state(ciphertext);

        //    - AddRoundKey (apply tweak modification at tweak_round)
        if (round == ctx->tweak_round) {
            // Apply tweak modification to the round key

            add_round_key(ctx, ciphertext, ciphertext, round);
            
        }else{
            printf("round [%d].k_sch ", round);
            print_state(&ctx->round_keys[round * 16]);
            add_round_key(ctx, ciphertext, ciphertext, round);
        }
    }
    
    // 3. Final round:
    //    - SubBytes
    sub_bytes(ciphertext);
    printf("round [%d].s_box ", round);
    print_state(ciphertext);
    //    - ShiftRows
    shift_rows(ciphertext);
    printf("round [%d].s_row ", round);
    print_state(ciphertext);
    //    - AddRoundKey
    add_round_key(ctx, ciphertext, ciphertext, round);
    printf("round [%d].k_sch ", round);
    print_state(&ctx->round_keys[round * 16]);
}

// Decrypt a single block
void taes_decrypt_block(const taes_ctx *ctx, const uint8_t *ciphertext, uint8_t *plaintext) {
    // TODO: Implement T-AES decryption
    // 1. Initial AddRoundKey
    uint8_t round = ctx->num_rounds - 1;
    add_round_key(ctx, ciphertext, plaintext, round);
    // 2. Rounds (num_rounds - 1) to 1:
    for (round = ctx->num_rounds - 1; round >= 1; round--) {
        //    - InvShiftRows
        inv_shift_rows(plaintext);
        //    - InvSubBytes
        inv_sub_bytes(plaintext);
        //    - AddRoundKey (apply tweak modification at tweak_round)
        if (round == ctx->tweak_round) {
            // Apply tweak modification to the round key
            add_round_key(ctx, ciphertext, ciphertext, round);
            
        }else{
            printf("Round key value: ");
            print_state(&ctx->round_keys[round * 16]);
            add_round_key(ctx, ciphertext, ciphertext, round);
        }
        //    - InvMixColumns
        inv_mix_columns(plaintext);
    }
    // 3. Final round:
    //    - InvShiftRows
    inv_shift_rows(plaintext);
    //    - InvSubBytes
    inv_sub_bytes(plaintext);
    //    - AddRoundKey
    add_round_key(ctx, plaintext, plaintext, round);
}

// Clean up context
void taes_cleanup(taes_ctx *ctx) {
    if (ctx) {
        memset(ctx, 0, sizeof(taes_ctx));
    }
}
