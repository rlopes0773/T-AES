#ifndef TAES_H
#define TAES_H

#include <stdint.h>
#include <stddef.h>

//  In AES, the 128-bit block (16 bytes) is conceptually arranged as a 4x4 matrix of bytes:

//   state[0]  state[4]  state[8]  state[12]
//   state[1]  state[5]  state[9]  state[13]
//   state[2]  state[6]  state[10] state[14]
//   state[3]  state[7]  state[11] state[15]

// AES block size (128 bits = 16 bytes)
#define AES_BLOCK_SIZE 16

// Tweak size (128 bits = 16 bytes)
#define TWEAK_SIZE 16

// Key sizes
#define AES_128_KEY_SIZE 16
#define AES_192_KEY_SIZE 24
#define AES_256_KEY_SIZE 32

// T-AES context structure
typedef struct {
    uint8_t round_keys[240];  // Maximum round keys for AES-256 (15 rounds * 16 bytes)
    uint8_t tweak[TWEAK_SIZE];
    int key_size;             // Key size in bytes (16, 24, or 32)
    int num_rounds;           // Number of rounds (10, 12, or 14)
    int tweak_round;          // Which round key to modify (5, 6, or 7)
} taes_ctx;

// Initialize T-AES context with key and tweak
// key_size: 16 (AES-128), 24 (AES-192), or 32 (AES-256)
int taes_init(taes_ctx *ctx, const uint8_t *key, int key_size, const uint8_t *tweak);

// Encrypt a single block (16 bytes)
void taes_encrypt_block(const taes_ctx *ctx, const uint8_t *plaintext, uint8_t *ciphertext);

// Decrypt a single block (16 bytes)
void taes_decrypt_block(const taes_ctx *ctx, const uint8_t *ciphertext, uint8_t *plaintext);

// Clean up context (zero out sensitive data)
void taes_cleanup(taes_ctx *ctx);

#endif // TAES_H
