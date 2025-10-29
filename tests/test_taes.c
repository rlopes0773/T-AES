// Test suite for T-AES implementation
#include "../include/taes.h"
#include "../include/counter_mode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Test vectors (standard AES test vectors can be used for basic validation)
// TODO: Add proper T-AES test vectors

// Test basic encryption/decryption
void test_basic_encrypt_decrypt(void) {
    printf("Testing basic encryption/decryption...\n");

    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t tweak[16] = {0};
    uint8_t plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    taes_ctx ctx;
    assert(taes_init(&ctx, key, 16, tweak) == 0);

    taes_encrypt_block(&ctx, plaintext, ciphertext);
    taes_decrypt_block(&ctx, ciphertext, decrypted);

    assert(memcmp(plaintext, decrypted, 16) == 0);
    printf("  PASSED: Encryption/decryption reversible\n");

    taes_cleanup(&ctx);
}

// Test that tweak changes output
void test_tweak_effect(void) {
    printf("Testing tweak effect...\n");

    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t tweak1[16] = {0};
    uint8_t tweak2[16] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t ciphertext1[16];
    uint8_t ciphertext2[16];

    taes_ctx ctx;

    // Encrypt with tweak1
    assert(taes_init(&ctx, key, 16, tweak1) == 0);
    taes_encrypt_block(&ctx, plaintext, ciphertext1);
    taes_cleanup(&ctx);

    // Encrypt with tweak2
    assert(taes_init(&ctx, key, 16, tweak2) == 0);
    taes_encrypt_block(&ctx, plaintext, ciphertext2);
    taes_cleanup(&ctx);

    // Ciphertexts should be different
    assert(memcmp(ciphertext1, ciphertext2, 16) != 0);
    printf("  PASSED: Different tweaks produce different ciphertexts\n");
}

// Test counter mode
void test_counter_mode(void) {
    printf("Testing counter mode...\n");

    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t tweak[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t plaintext[64];
    uint8_t ciphertext[64];
    uint8_t decrypted[64];

    // Initialize plaintext
    for (int i = 0; i < 64; i++) {
        plaintext[i] = i;
    }

    taes_ctx ctx;
    assert(taes_init(&ctx, key, 16, tweak) == 0);

    // Encrypt
    assert(counter_mode_encrypt(&ctx, plaintext, ciphertext, 64) == 0);

    // Decrypt
    assert(counter_mode_decrypt(&ctx, ciphertext, decrypted, 64) == 0);

    // Verify
    assert(memcmp(plaintext, decrypted, 64) == 0);
    printf("  PASSED: Counter mode encryption/decryption reversible\n");

    taes_cleanup(&ctx);
}

// Test all key sizes
void test_key_sizes(void) {
    printf("Testing different key sizes...\n");

    uint8_t key128[16] = {0};
    uint8_t key192[24] = {0};
    uint8_t key256[32] = {0};
    uint8_t tweak[16] = {0};
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    taes_ctx ctx;

    // Test 128-bit key
    assert(taes_init(&ctx, key128, 16, tweak) == 0);
    taes_encrypt_block(&ctx, plaintext, ciphertext);
    taes_decrypt_block(&ctx, ciphertext, decrypted);
    assert(memcmp(plaintext, decrypted, 16) == 0);
    taes_cleanup(&ctx);
    printf("  PASSED: AES-128\n");

    // Test 192-bit key
    assert(taes_init(&ctx, key192, 24, tweak) == 0);
    taes_encrypt_block(&ctx, plaintext, ciphertext);
    taes_decrypt_block(&ctx, ciphertext, decrypted);
    assert(memcmp(plaintext, decrypted, 16) == 0);
    taes_cleanup(&ctx);
    printf("  PASSED: AES-192\n");

    // Test 256-bit key
    assert(taes_init(&ctx, key256, 32, tweak) == 0);
    taes_encrypt_block(&ctx, plaintext, ciphertext);
    taes_decrypt_block(&ctx, ciphertext, decrypted);
    assert(memcmp(plaintext, decrypted, 16) == 0);
    taes_cleanup(&ctx);
    printf("  PASSED: AES-256\n");
}

int main(void) {
    printf("T-AES Test Suite\n");
    printf("================\n\n");

    test_basic_encrypt_decrypt();
    test_tweak_effect();
    test_counter_mode();
    test_key_sizes();

    printf("\nAll tests passed!\n");
    return 0;
}
