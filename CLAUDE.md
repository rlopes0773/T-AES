# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

T-AES (Tweakable AES) implementation for Applied Cryptography coursework. This is a custom AES variant that inserts a 128-bit tweak into the middle of the AES substitution-permutation network using arithmetic addition (not XOR).

## Build Commands

```bash
# Build all components
make

# Build specific targets
make taes          # Standard implementation only
make taes-ni       # AES-NI hardware-accelerated version
make apps          # All applications
make tests         # Test suite

# Clean
make clean

# Run tests
make test
./tests/test_taes
```

## Code Architecture

### Core Implementation Strategy

**T-AES Tweak Mechanism:**
- Tweak is applied to ONE specific round key via arithmetic addition
- Round key selection depends on AES key size:
  - 128-bit keys: modify RK5
  - 192-bit keys: modify RK6
  - 256-bit keys: modify RK7
- **IMPORTANT**: Both encryption AND decryption use addition (NOT subtraction):
  - Encryption: `modified_rk = original_rk + tweak` (128-bit arithmetic)
  - Decryption: `modified_rk = original_rk + tweak` (128-bit arithmetic)
  - Note: For AES-NI implementation, tweak is added before the round key transformation during decryption

**Dual Implementation Approach:**
- `src/taes.c`: Standard C implementation using lookup tables
- `src/taes_ni.c`: AES-NI hardware acceleration using Intel intrinsics (`_mm_aesenc_si128`, `_mm_aesdec_si128`, etc.)
- Both must implement same API in `include/taes.h`

**Counter Mode with Incrementing Tweaks:**
- ECB-based mode in `src/counter_mode.c`
- Each block uses tweak + block_index: `E(K, P[i], tweak + i)`
- Implements Ciphertext Stealing for non-block-aligned data (requires >16 bytes input)

### Application Layer

Four main applications in `apps/`:
- `encrypt.c`: Encrypts stdin to stdout, derives keys from passwords
- `decrypt.c`: Decrypts stdin to stdout
- `speed.c`: Benchmark comparing T-AES counter mode vs XTS (with/without AES-NI)
- `stat.c`: Statistical analysis showing Hamming distance distribution under tweak changes

### Key Technical Requirements

**Key Derivation:**
- Use OpenSSL's key derivation functions
- Support all AES key sizes: 128, 192, 256 bits
- Separate derivation for main key and tweak (when provided)

**Performance Benchmarking (`apps/speed.c`):**
- Use 4KB buffers (one memory page)
- Minimum 100,000 measurements per configuration
- Use `clock_gettime()` for nanosecond precision
- Report minimum times (maximum throughput)
- Compare: XTS vs T-AES, with/without AES-NI

**AES-NI Compilation:**
- Compile with `-maes` flag
- Use `<wmmintrin.h>` for Intel intrinsics
- Check CPU support: `grep -o aes /proc/cpuinfo`

## Important Implementation Notes

- T-AES uses arithmetic addition for tweak application (for BOTH encryption and decryption), NOT XOR or subtraction
- Ciphertext Stealing requires input length > 16 bytes (more than one block)
- The tweak is applied internally to a round key, not at input/output like XTS
- Both standard and AES-NI versions must produce identical outputs for same inputs
- **CRITICAL**: The specification was corrected in v1.1 - decryption also uses addition, NOT subtraction
