// Test basic AES implementation (without tweak) against known test vectors
#include "../include/taes.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

// NIST FIPS-197 AES test vectors
// https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf

void test_aes128_encrypt(void) {
    printf("Testing AES-128 encryption (NIST test vector)...\n");

    // NIST FIPS-197 Appendix B
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };

    // Expected ciphertext for above key and plaintext
    uint8_t expected[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };

    uint8_t ciphertext[16];
    uint8_t tweak[16] = {0}; // Zero tweak = standard AES

    taes_ctx ctx;
    assert(taes_init(&ctx, key, 16, tweak) == 0);

    taes_encrypt_block(&ctx, plaintext, ciphertext);

    printf("  Key:        ");
    for(int i = 0; i < 16; i++) printf("%02x ", key[i]);
    printf("\n");

    printf("  Plaintext:  ");
    for(int i = 0; i < 16; i++) printf("%02x ", plaintext[i]);
    printf("\n");

    printf("  Expected:   ");
    for(int i = 0; i < 16; i++) printf("%02x ", expected[i]);
    printf("\n");

    printf("  Got:        ");
    for(int i = 0; i < 16; i++) printf("%02x ", ciphertext[i]);
    printf("\n");

    if (memcmp(ciphertext, expected, 16) == 0) {
        printf("  ✓ PASSED: Matches NIST test vector\n");
    } else {
        printf("  ✗ FAILED: Does not match expected output\n");
    }

    taes_cleanup(&ctx);
}

void test_aes128_decrypt(void) {
    printf("\nTesting AES-128 decryption (NIST test vector)...\n");

    uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    uint8_t ciphertext[16] = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
    };

    uint8_t expected[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    uint8_t plaintext[16];
    uint8_t tweak[16] = {0}; // Zero tweak = standard AES

    taes_ctx ctx;
    assert(taes_init(&ctx, key, 16, tweak) == 0);

    taes_decrypt_block(&ctx, ciphertext, plaintext);

    printf("  Ciphertext: ");
    for(int i = 0; i < 16; i++) printf("%02x ", ciphertext[i]);
    printf("\n");

    printf("  Expected:   ");
    for(int i = 0; i < 16; i++) printf("%02x ", expected[i]);
    printf("\n");

    printf("  Got:        ");
    for(int i = 0; i < 16; i++) printf("%02x ", plaintext[i]);
    printf("\n");

    if (memcmp(plaintext, expected, 16) == 0) {
        printf("  ✓ PASSED: Matches NIST test vector\n");
    } else {
        printf("  ✗ FAILED: Does not match expected output\n");
    }

    taes_cleanup(&ctx);
}

void test_reversibility(void) {
    printf("\nTesting encrypt/decrypt reversibility...\n");

    uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t plaintext[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                             0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    uint8_t tweak[16] = {0};

    taes_ctx ctx;
    taes_init(&ctx, key, 16, tweak);

    taes_encrypt_block(&ctx, plaintext, ciphertext);
    taes_decrypt_block(&ctx, ciphertext, decrypted);

    printf("  Plaintext:  ");
    for(int i = 0; i < 16; i++) printf("%02x ", plaintext[i]);
    printf("\n");

    printf("  Ciphertext: ");
    for(int i = 0; i < 16; i++) printf("%02x ", ciphertext[i]);
    printf("\n");

    printf("  Decrypted:  ");
    for(int i = 0; i < 16; i++) printf("%02x ", decrypted[i]);
    printf("\n");

    if (memcmp(plaintext, decrypted, 16) == 0) {
        printf("  ✓ PASSED: Decrypt(Encrypt(P)) = P\n");
    } else {
        printf("  ✗ FAILED: Decryption did not recover original plaintext\n");
    }

    taes_cleanup(&ctx);
}

int main(void) {
    printf("========================================\n");
    printf("Basic AES Test (Zero Tweak)\n");
    printf("========================================\n\n");

    test_aes128_encrypt();
    test_aes128_decrypt();
    test_reversibility();

    printf("\n========================================\n");
    printf("Testing complete!\n");
    printf("========================================\n");

    return 0;
}
