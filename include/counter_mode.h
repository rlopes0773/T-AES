#ifndef COUNTER_MODE_H
#define COUNTER_MODE_H

#include <stdint.h>
#include <stddef.h>
#include "taes.h"

// Encrypt data using T-AES counter mode with incrementing tweaks
// Each block uses: E(K, P[i], tweak + i)
// Uses Ciphertext Stealing for non-block-aligned data (requires length > 16 bytes)
int counter_mode_encrypt(const taes_ctx *ctx, const uint8_t *plaintext,
                         uint8_t *ciphertext, size_t length);

// Decrypt data using T-AES counter mode with incrementing tweaks
// Uses Ciphertext Stealing for non-block-aligned data (requires length > 16 bytes)
int counter_mode_decrypt(const taes_ctx *ctx, const uint8_t *ciphertext,
                         uint8_t *plaintext, size_t length);

#endif // COUNTER_MODE_H
