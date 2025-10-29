// Test basic AES implementation (without tweak) against known test vectors
#include "../include/taes.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

// NIST FIPS-197 AES test vectors (Appendix C)
// https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf

typedef struct {
    int key_bits;
    size_t key_bytes;
    uint8_t key[32];
    uint8_t plaintext[16];
    uint8_t ciphertext[16];
} aes_tv_t;

// Test vectors from FIPS-197 Appendix C
static const aes_tv_t test_vectors[] = {
    // AES-128
    {
        .key_bits = 128,
        .key_bytes = 16,
        .key = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
        },
        .plaintext = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
        },
        .ciphertext = {
            0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
            0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
        }
    },
    // AES-192
    {
        .key_bits = 192,
        .key_bytes = 24,
        .key = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
        },
        .plaintext = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
        },
        .ciphertext = {
            0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,
            0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91
        }
    },
    // AES-256
    {
        .key_bits = 256,
        .key_bytes = 32,
        .key = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
        },
        .plaintext = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
        },
        .ciphertext = {
            0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
            0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89
        }
    }
};

static const size_t test_vector_count = sizeof(test_vectors) / sizeof(test_vectors[0]);

void test_all_encrypt(void) {
    printf("Testing AES encryption (all key sizes)...\n\n");

    for (size_t i = 0; i < test_vector_count; i++) {
        const aes_tv_t *tv = &test_vectors[i];

        printf("  AES-%d encryption:\n", tv->key_bits);

        uint8_t ciphertext[16];
        uint8_t tweak[16] = {0}; // Zero tweak = standard AES

        taes_ctx ctx;
        assert(taes_init(&ctx, tv->key, tv->key_bytes, tweak) == 0);

        taes_encrypt_block(&ctx, tv->plaintext, ciphertext);

        printf("    Key (%zu bytes): ", tv->key_bytes);
        for(size_t j = 0; j < tv->key_bytes; j++) printf("%02x ", tv->key[j]);
        printf("\n");

        printf("    Plaintext:       ");
        for(int j = 0; j < 16; j++) printf("%02x ", tv->plaintext[j]);
        printf("\n");

        printf("    Expected:        ");
        for(int j = 0; j < 16; j++) printf("%02x ", tv->ciphertext[j]);
        printf("\n");

        printf("    Got:             ");
        for(int j = 0; j < 16; j++) printf("%02x ", ciphertext[j]);
        printf("\n");

        if (memcmp(ciphertext, tv->ciphertext, 16) == 0) {
            printf("    ✓ PASSED\n");
        } else {
            printf("    ✗ FAILED\n");
        }
        printf("\n");

        taes_cleanup(&ctx);
    }
}

void test_all_decrypt(void) {
    printf("Testing AES decryption (all key sizes)...\n\n");

    for (size_t i = 0; i < test_vector_count; i++) {
        const aes_tv_t *tv = &test_vectors[i];

        printf("  AES-%d decryption:\n", tv->key_bits);

        uint8_t plaintext[16];
        uint8_t tweak[16] = {0}; // Zero tweak = standard AES

        taes_ctx ctx;
        assert(taes_init(&ctx, tv->key, tv->key_bytes, tweak) == 0);

        taes_decrypt_block(&ctx, tv->ciphertext, plaintext);

        printf("    Ciphertext:      ");
        for(int j = 0; j < 16; j++) printf("%02x ", tv->ciphertext[j]);
        printf("\n");

        printf("    Expected:        ");
        for(int j = 0; j < 16; j++) printf("%02x ", tv->plaintext[j]);
        printf("\n");

        printf("    Got:             ");
        for(int j = 0; j < 16; j++) printf("%02x ", plaintext[j]);
        printf("\n");

        if (memcmp(plaintext, tv->plaintext, 16) == 0) {
            printf("    ✓ PASSED\n");
        } else {
            printf("    ✗ FAILED\n");
        }
        printf("\n");

        taes_cleanup(&ctx);
    }
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
    printf("All Key Sizes: 128, 192, 256 bits\n");
    printf("========================================\n\n");

    test_all_encrypt();
    test_all_decrypt();
    test_reversibility();

    printf("\n========================================\n");
    printf("Testing complete!\n");
    printf("========================================\n");

    return 0;
}
