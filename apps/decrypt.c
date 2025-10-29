// Decryption application - reads from stdin, writes to stdout
#include "../include/taes.h"
#include "../include/counter_mode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// External functions from utils.c
extern int derive_key_from_password(const char *password, uint8_t *key, int key_size);
extern int derive_tweak_from_password(const char *password, uint8_t *tweak);

int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s <key_size> <password> [tweak_password]\n", argv[0]);
        fprintf(stderr, "  key_size: 128, 192, or 256\n");
        fprintf(stderr, "  password: Password for key derivation\n");
        fprintf(stderr, "  tweak_password: Optional password for tweak (enables counter mode)\n");
        return 1;
    }

    // Parse key size
    int key_bits = atoi(argv[1]);
    int key_size;
    switch (key_bits) {
        case 128: key_size = 16; break;
        case 192: key_size = 24; break;
        case 256: key_size = 32; break;
        default:
            fprintf(stderr, "Invalid key size. Must be 128, 192, or 256.\n");
            return 1;
    }

    // Derive key from password
    uint8_t key[32];
    if (derive_key_from_password(argv[2], key, key_size) != 0) {
        fprintf(stderr, "Key derivation failed\n");
        return 1;
    }

    // Initialize T-AES context
    taes_ctx ctx;
    uint8_t tweak[TWEAK_SIZE] = {0};
    int use_counter_mode = 0;

    if (argc == 4) {
        // Derive tweak from password
        if (derive_tweak_from_password(argv[3], tweak) != 0) {
            fprintf(stderr, "Tweak derivation failed\n");
            return 1;
        }
        use_counter_mode = 1;
    }

    if (taes_init(&ctx, key, key_size, tweak) != 0) {
        fprintf(stderr, "T-AES initialization failed\n");
        return 1;
    }

    // TODO: Read ciphertext from stdin
    // TODO: Decrypt using either ECB mode (single block) or counter mode (multiple blocks)
    // TODO: Write plaintext to stdout

    // Clean up
    taes_cleanup(&ctx);
    memset(key, 0, sizeof(key));
    memset(tweak, 0, sizeof(tweak));

    return 0;
}
