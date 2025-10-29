# T-AES Implementation TODO List

Based on TAES.pdf v1.1 specification and current codebase analysis.

**Due Date**: November 9, 2025

---

## CRITICAL SPECIFICATION CHANGES (v1.1)

- [x] **FIX src/taes_ni.c:53** - Comment incorrectly says "arithmetic subtraction" for decryption
- [x] **IMPORTANT**: Both encryption AND decryption must use **arithmetic addition** for tweak
- [ ] Update all code comments that reference tweak subtraction
- [ ] Verify implementation uses addition in both encrypt/decrypt paths

---

## CORE IMPLEMENTATION - 40% of grade

### 1. Standard T-AES (src/taes.c) - 10%

**File**: `src/taes.c`

- [x] Complete AES key expansion in `taes_init()` (line 108)
  - Expand key into round_keys array
  - Support 128-bit (10 rounds), 192-bit (12 rounds), 256-bit (14 rounds)
- [x] Implement MixColumns transformation function
- [ ] Implement InvMixColumns transformation function
- [ ] Fix ShiftRows function (I think it's changing the columns not the rows)
- [ ] Implement `taes_encrypt_block()` (line 123)
  - Initial AddRoundKey with RK[0]
  - Rounds 1 to (num_rounds - 1):
    - SubBytes (using sbox)
    - ShiftRows
    - MixColumns
    - AddRoundKey
    - **At tweak_round (5/6/7): Add tweak to round key using 128-bit arithmetic**
  - Final round (num_rounds):
    - SubBytes
    - ShiftRows
    - AddRoundKey (no MixColumns)
- [ ] Implement `taes_decrypt_block()` (line 138)
  - Initial AddRoundKey with RK[num_rounds]
  - Rounds (num_rounds - 1) down to 1:
    - InvShiftRows
    - InvSubBytes (using inv_sbox)
    - AddRoundKey
    - **At tweak_round (5/6/7): Add tweak to round key using 128-bit arithmetic**
    - InvMixColumns
  - Final round:
    - InvShiftRows
    - InvSubBytes
    - AddRoundKey with RK[0]

**Technical Notes**:
- Use GCC `__int128` or `unsigned __int128` for 128-bit arithmetic addition
- Tweak modification: `modified_rk = original_rk + tweak` (for BOTH encrypt and decrypt)

---

### 2. AES-NI T-AES (src/taes_ni.c) - 20%

**File**: `src/taes_ni.c`

- [ ] Implement AES-NI key expansion in `taes_init_ni()` (line 27)
  - Use `_mm_aeskeygenassist_si128()` for round constant generation
  - Implement the `get_round_key()` helper from PDF page 5
  - Support 128-bit, 192-bit, 256-bit key expansion
- [ ] Implement 128-bit arithmetic addition helper function
  - Add tweak to round key as unsigned 128-bit integers
  - Use `__m128i` type for compatibility with intrinsics
- [ ] Implement `taes_encrypt_block_ni()` (line 40)
  - Load plaintext into `__m128i` register
  - Initial XOR with RK[0]
  - Rounds 1 to (num_rounds - 1):
    - Use `_mm_aesenc_si128(state, RK[i])`
    - **At tweak_round (5/6/7): Add tweak to RK before applying**
  - Final round:
    - Use `_mm_aesenclast_si128(state, RK[num_rounds])`
  - Store result to ciphertext
- [ ] Implement `taes_decrypt_block_ni()` (line 48)
  - Load ciphertext into `__m128i` register
  - Transform round keys 1-9 using `_mm_aesimc_si128()` for decryption
  - Initial XOR with RK[num_rounds]
  - Rounds (num_rounds - 1) down to 1:
    - Use `_mm_aesdec_si128(state, transformed_RK[i])`
    - **At tweak_round (5/6/7): Add tweak to RK BEFORE transformation**
  - Final round:
    - Use `_mm_aesdeclast_si128(state, RK[0])`
  - Store result to plaintext

**Technical Notes**:
- Include `<wmmintrin.h>` for AES-NI intrinsics
- Compile with `-maes` flag
- **CRITICAL**: v1.1 spec clarifies decryption also uses addition, NOT subtraction
- For AES-NI decryption: add tweak before `_mm_aesimc_si128()` transformation

---

### 3. Counter Mode with Ciphertext Stealing (src/counter_mode.c) - 10%

**File**: `src/counter_mode.c`

- [ ] Implement `counter_mode_encrypt()` (line 26)
  - Calculate number of complete blocks
  - For each complete block `i`:
    - Create temporary context with `tweak + i`
    - Encrypt: `C[i] = E(K, P[i], tweak + i)`
    - Increment tweak by 1 (using 128-bit arithmetic)
  - If partial last block exists (length not block-aligned):
    - Apply ECB Ciphertext Stealing on last two blocks
    - Encrypt penultimate block with `tweak + (n-2)`
    - Pad last partial block with bytes from penultimate ciphertext
    - Encrypt padded last block with `tweak + (n-1)`
    - Swap and truncate according to Ciphertext Stealing
- [ ] Implement `counter_mode_decrypt()` (line 51)
  - Calculate number of complete blocks
  - For each complete block `i`:
    - Create temporary context with `tweak + i`
    - Decrypt: `P[i] = D(K, C[i], tweak + i)`
    - Increment tweak by 1
  - If partial last block exists:
    - Reverse Ciphertext Stealing process
    - Decrypt blocks in correct order with appropriate tweaks

**Technical Notes**:
- Requires input length > 16 bytes (more than one block)
- See: https://en.wikipedia.org/wiki/Ciphertext_stealing
- Tweak increment: use existing `increment_tweak()` helper

---

## APPLICATIONS - 40% of grade

### 4. Encrypt Application (apps/encrypt.c) - 10%

**File**: `apps/encrypt.c`

- [ ] Complete stdin reading implementation
  - Use binary mode reading
  - Implement buffering strategy (read blocks, keep last block on hold)
  - Detect end-of-stream to determine if last block is partial
- [ ] Implement mode selection logic
  - If `argc == 3`: Use ECB mode (no tweak, direct block encryption)
  - If `argc == 4`: Use counter mode with tweak
- [ ] Implement ECB mode encryption path
  - Encrypt each complete block independently
  - Handle last block with Ciphertext Stealing if needed
- [ ] Implement counter mode encryption path
  - Call `counter_mode_encrypt()` with derived tweak
- [ ] Write encrypted output to stdout (binary mode)
- [ ] Proper memory cleanup and error handling

**Usage**: `./encrypt <key_size> <password> [tweak_password]`

---

### 5. Decrypt Application (apps/decrypt.c) - 10%

**File**: `apps/decrypt.c`

- [ ] Complete stdin reading implementation (binary mode)
- [ ] Implement mode selection logic
  - If `argc == 3`: Use ECB mode decryption
  - If `argc == 4`: Use counter mode decryption
- [ ] Implement ECB mode decryption path
  - Decrypt each block independently
  - Reverse Ciphertext Stealing if needed
- [ ] Implement counter mode decryption path
  - Call `counter_mode_decrypt()` with derived tweak
- [ ] Write decrypted output to stdout (binary mode)
- [ ] Proper memory cleanup and error handling

**Usage**: `./decrypt <key_size> <password> [tweak_password]`

---

### 6. Speed Benchmark Application (apps/speed.c) - 10%

**File**: `apps/speed.c`

- [ ] Allocate 4KB (4096 bytes) buffer
- [ ] Fill buffer with random data from `/dev/urandom`
- [ ] Implement XTS encryption using OpenSSL library
  - Initialize XTS context
  - Measure encryption time
  - Measure decryption time
- [ ] Implement XTS with AES-NI (if library supports)
- [ ] Implement T-AES counter mode (standard implementation)
  - Link with `src/taes.c`
  - Measure encryption/decryption
- [ ] Implement T-AES counter mode (AES-NI implementation)
  - Link with `src/taes_ni.c`
  - Measure encryption/decryption
- [ ] Measurement loop:
  - Generate new random key for each iteration
  - Generate new random tweak for each iteration
  - Perform at least 100,000 measurements per configuration
  - Use `clock_gettime(CLOCK_MONOTONIC, ...)` for nanosecond precision
  - Record only encryption/decryption time (exclude key setup)
  - Track minimum time (maximum throughput)
- [ ] Output results:
  - Report minimum times for each configuration
  - Calculate and display throughput (MB/s or GB/s)
  - Compare: XTS vs T-AES, standard vs AES-NI

**Configurations to Test**:
1. XTS (standard)
2. XTS + AES-NI
3. T-AES counter mode (standard)
4. T-AES counter mode + AES-NI

---

### 7. Statistical Analysis Application (apps/stat.c) - 10%

**File**: `apps/stat.c`

- [ ] Generate random 128-bit input block
- [ ] Generate random initial 128-bit tweak
- [ ] Initialize T-AES context with random key
- [ ] Measurement loop (e.g., 10,000+ iterations):
  - Encrypt input block with current tweak: `C1 = E(K, P, tweak)`
  - Increment tweak by 1
  - Encrypt same block with new tweak: `C2 = E(K, P, tweak+1)`
  - Calculate Hamming distance between C1 and C2
  - Record Hamming distance in histogram
  - Set C1 = C2 for next iteration
- [ ] Build probability distribution:
  - Count occurrences of each Hamming distance (0-128)
  - Calculate probabilities (count / total_measurements)
- [ ] Generate output chart/histogram:
  - Can use ASCII art for simple display
  - Or output CSV for plotting with external tools (gnuplot, matplotlib)
- [ ] Display statistics:
  - Mean Hamming distance
  - Standard deviation
  - Expected result: ~64 bits difference (ideal diffusion)

**Purpose**: Verify that changing the tweak produces good avalanche effect

---

## UTILITIES & INFRASTRUCTURE

### 8. Key Derivation (src/utils.c)

**File**: `src/utils.c`

- [ ] Verify `derive_key_from_password()` implementation
  - Uses OpenSSL PBKDF2 or similar KDF
  - Supports key sizes: 16, 24, 32 bytes
  - Uses appropriate salt and iteration count
- [ ] Verify `derive_tweak_from_password()` implementation
  - Uses separate derivation from key
  - Always produces 16-byte tweak
  - Different salt/parameters from key derivation

---

### 9. Testing Suite (tests/test_taes.c)

**File**: `tests/test_taes.c`

- [ ] Test AES compatibility (T-AES with zero tweak == standard AES)
  - Compare against OpenSSL AES output
- [ ] Test all key sizes
  - 128-bit key (10 rounds, tweak at RK5)
  - 192-bit key (12 rounds, tweak at RK6)
  - 256-bit key (14 rounds, tweak at RK7)
- [ ] Test encryption/decryption round-trip
  - `D(E(P, K, T), K, T) == P`
- [ ] Test standard vs AES-NI equivalence
  - `taes_encrypt_block() == taes_encrypt_block_ni()` for same inputs
  - `taes_decrypt_block() == taes_decrypt_block_ni()` for same inputs
- [ ] Test tweak modification
  - Different tweaks produce different ciphertexts
  - **Verify both encrypt and decrypt use addition**
- [ ] Test Ciphertext Stealing
  - Various non-block-aligned lengths
  - Edge cases: exactly 1 block + 1 byte, nearly 2 blocks, etc.
- [ ] Test counter mode
  - Multiple blocks with incrementing tweaks
  - Partial last block handling
  - Verify tweak increments correctly

---

## BUILD & DEPLOYMENT

### 10. Build System

**File**: `Makefile`

- [ ] Verify `make` builds all targets
- [ ] Verify `make taes` builds standard implementation
- [ ] Verify `make taes-ni` builds AES-NI version with `-maes` flag
- [ ] Verify `make apps` builds all four applications
- [ ] Verify `make tests` builds test suite
- [ ] Verify `make test` runs test suite
- [ ] Verify `make clean` removes build artifacts
- [ ] Test compilation on target Linux system
- [ ] Check CPU AES-NI support: `grep -o aes /proc/cpuinfo`

---

## DOCUMENTATION - 20% of grade

### 11. Report Writing

**File**: `docs/report.pdf` (max 10 pages)

- [ ] Introduction
  - Explain T-AES concept
  - Differences from XTS/XEX modes
- [ ] Implementation Strategy
  - T-AES tweak mechanism (addition at specific round key)
  - Standard C implementation approach
  - AES-NI implementation approach
  - **Note v1.1 correction: addition for both encrypt/decrypt**
- [ ] Counter Mode Implementation
  - Incrementing tweak mechanism
  - Ciphertext Stealing approach
- [ ] Application Design
  - Key derivation strategy
  - stdin/stdout processing
  - Mode selection logic
- [ ] Performance Analysis
  - Speed benchmark results
  - Comparison: T-AES vs XTS
  - Comparison: standard vs AES-NI
  - Throughput analysis
- [ ] Statistical Analysis
  - Hamming distance distribution results
  - Chart/graph of probability distribution
  - Analysis of diffusion properties
- [ ] Code Attribution
  - Cite any external code sources
  - Document any library usage
- [ ] Appendix (optional)
  - Key code snippets (not full source)
  - Build instructions

---

## BONUS TASKS - 10% extra credit

### 12. OpenSSL Speed Integration (Optional)

- [ ] Download OpenSSL source code
- [ ] Study `openssl speed` command implementation
- [ ] Add XTS mode to speed benchmark
- [ ] Add T-AES implementation
- [ ] Add ECB-based counter mode
- [ ] Integrate into OpenSSL build system
- [ ] Test `openssl speed` with new modes
- [ ] Document integration process

---

## VERIFICATION CHECKLIST

### Pre-Submission Tests

- [ ] All code compiles without warnings (`-Wall -Wextra`)
- [ ] Test suite passes all tests
- [ ] Encrypt/decrypt round-trip works for various inputs
- [ ] Standard and AES-NI produce identical outputs
- [ ] Speed benchmark runs and produces results
- [ ] Statistical analysis produces reasonable distribution
- [ ] Report is complete and under 10 pages
- [ ] All external code is properly attributed
- [ ] Code is properly commented
- [ ] README.md has build/usage instructions

### Critical Implementation Verification

- [ ] **CONFIRM: Encryption uses arithmetic addition for tweak**
- [ ] **CONFIRM: Decryption uses arithmetic addition for tweak (NOT subtraction)**
- [ ] **CONFIRM: Both standard and AES-NI use same tweak operation**
- [ ] **CONFIRM: Tweak applied at correct round (RK5/6/7 based on key size)**

---

## SUBMISSION

- [ ] Package all source code
- [ ] Include Makefile
- [ ] Include report (PDF, max 10 pages)
- [ ] Include README with build instructions
- [ ] Test on clean system (verify dependencies)
- [ ] Submit via eLearning before November 9, 2025

---

## NOTES

**Important Specification Changes**:
- v1.1 removed incorrect reference to tweak subtraction in decryption
- Both encryption and decryption use **arithmetic addition** for tweak
- For AES-NI: tweak is added before round key transformation in decryption

**References**:
- Intel AES-NI White Paper: https://www.intel.com/content/dam/develop/external/us/en/documents/aes-wp-2012-09-22-v01-165683.pdf
- NIST FIPS 197 (AES): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
- Ciphertext Stealing: https://en.wikipedia.org/wiki/Ciphertext_stealing

**Grading Breakdown**:
- T-AES standard: 10%
- T-AES AES-NI: 20%
- Counter mode: 10%
- encrypt app: 10%
- decrypt app: 10%
- speed app: 10%
- stat app: 10%
- Report: 20%
- Bonus: +10%
