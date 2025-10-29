// Statistical analysis application
// Shows Hamming distance distribution when tweak changes
#include "../include/taes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_SAMPLES 10000
#define AES_BLOCK_SIZE 16

// Calculate Hamming distance between two blocks
static int hamming_distance(const uint8_t *block1, const uint8_t *block2, size_t len) {
    int distance = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t xor_val = block1[i] ^ block2[i];
        // Count set bits
        while (xor_val) {
            distance += xor_val & 1;
            xor_val >>= 1;
        }
    }
    return distance;
}

int main(void) {
    printf("T-AES Statistical Analysis\n");
    printf("Analyzing Hamming distance distribution under tweak changes\n");
    printf("Samples: %d\n\n", NUM_SAMPLES);

    // TODO: Implement statistical analysis
    // 1. Generate random plaintext blocks
    // 2. For each block:
    //    a. Encrypt with tweak T1
    //    b. Encrypt with tweak T2 (slightly different)
    //    c. Calculate Hamming distance between ciphertexts
    // 3. Build histogram of Hamming distances
    // 4. Calculate probability distribution
    // 5. Display results

    // Expected result: Hamming distances should be approximately normally
    // distributed around 64 bits (half of 128 bits), showing good diffusion

    int histogram[129] = {0};  // 0 to 128 bits different

    // TODO: Fill histogram

    // Display histogram
    printf("Hamming Distance | Count | Probability\n");
    printf("-----------------|-------|------------\n");
    for (int i = 0; i <= 128; i++) {
        if (histogram[i] > 0) {
            double prob = (double)histogram[i] / NUM_SAMPLES;
            printf("%16d | %5d | %10.6f\n", i, histogram[i], prob);
        }
    }

    return 0;
}
