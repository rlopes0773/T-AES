# T-AES: Tweakable AES Implementation

A custom implementation of Tweakable AES (T-AES) with hardware acceleration support for the Cybersecurity MSc Applied Cryptography course (2025-26).

## Overview

T-AES is a modified version of AES that introduces a 128-bit tweak parameter inserted into the middle of the AES substitution-permutation network. Unlike traditional tweakable modes like XTS that apply tweaks at input/output, T-AES applies the tweak once to a specific round key using arithmetic addition.

### Key Features

- ✅ Standard C/C++ implementation
- ✅ Hardware-accelerated version using Intel AES-NI instructions
- ✅ Support for all AES key sizes (128, 192, 256 bits)
- ✅ ECB-based counter mode with incrementing tweaks
- ✅ Ciphertext Stealing for non-block-aligned data
- ✅ Performance benchmarking against XTS
- ✅ Statistical analysis tools

## Project Structure

```
.
├── src/
│   ├── taes.c              # Core T-AES implementation (standard)
│   ├── taes_ni.c           # T-AES with AES-NI instructions
│   ├── counter_mode.c      # ECB counter mode implementation
│   └── utils.c             # Helper functions (key derivation, etc.)
├── apps/
│   ├── encrypt.c           # Encryption application
│   ├── decrypt.c           # Decryption application
│   ├── speed.c             # Performance benchmarking
│   └── stat.c              # Statistical analysis
├── include/
│   ├── taes.h
│   └── counter_mode.h
├── tests/
│   └── test_taes.c         # Unit tests
├── docs/
│   └── report.pdf          # Project report
├── Makefile
└── README.md
```

## Building

### Prerequisites

- GCC or Clang with C11 support
- OpenSSL development libraries
- CPU with AES-NI support (for hardware-accelerated version)
- Linux operating system

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install build-essential libssl-dev

# Check for AES-NI support
grep -o aes /proc/cpuinfo
```

### Compilation

```bash
# Build all components
make

# Build specific targets
make taes          # Standard implementation only
make taes-ni       # AES-NI implementation only
make apps          # All applications
make tests         # Test suite

# Clean build artifacts
make clean
```

## Usage

### Encrypt Application

```bash
# Encrypt with standard AES (ECB mode)
./encrypt 128 password < plaintext.bin > ciphertext.bin

# Encrypt with T-AES counter mode
./encrypt 256 password tweak_password < plaintext.bin > ciphertext.bin
```

**Parameters:**

- First argument: Key size (128, 192, or 256)
- Second argument: Password for AES key derivation
- Third argument (optional): Password for tweak derivation

### Decrypt Application

```bash
# Decrypt standard AES
./decrypt 128 password < ciphertext.bin > plaintext.bin

# Decrypt T-AES counter mode
./decrypt 256 password tweak_password < ciphertext.bin > plaintext.bin
```

### Speed Benchmark

```bash
# Run performance comparison
./speed

# Output shows minimum encryption/decryption times for:
# - XTS (library) with/without AES-NI
# - T-AES counter mode with/without AES-NI
```

**Methodology:**

- 4KB buffer (one memory page)
- 100,000+ measurements per configuration
- Reports minimum time (maximum throughput)
- Uses `clock_gettime()` for nanosecond precision

### Statistical Analysis

```bash
# Analyze tweak effect on output
./stat

# Generates Hamming distance probability distribution
# Shows how tweak changes affect ciphertext
```

## Technical Details

### T-AES Algorithm

T-AES modifies standard AES by applying a 128-bit tweak to a specific round key:

| Key Size | Modified Round Key |
|----------|-------------------|
| 128-bit  | RK5               |
| 192-bit  | RK6               |
| 256-bit  | RK7               |

**Key Modification:**

```c
// During encryption
modified_rk = original_rk + tweak  // 128-bit arithmetic addition

// During decryption
modified_rk = original_rk - tweak  // 128-bit arithmetic subtraction

```

⚠️ **Important:** Uses arithmetic addition/subtraction, NOT XOR!

### Counter Mode

The ECB-based counter mode increments the tweak for each block:

```
Block 1: E(K, P1, tweak)
Block 2: E(K, P2, tweak + 1)
Block 3: E(K, P3, tweak + 2)
...
```

### Ciphertext Stealing

For non-block-aligned inputs, the last two blocks use Ciphertext Stealing to avoid padding:

1. Encrypt the penultimate block normally
2. Use output bytes to pad the last partial block
3. Encrypt the padded block
4. Swap and truncate appropriately

⚠️ **Note:** Requires input > 16 bytes (more than one AES block)

### AES-NI Implementation

Uses Intel intrinsics for hardware acceleration:

```c
_mm_aesenc_si128()      // Encryption round
_mm_aesenclast_si128()  // Final encryption round
_mm_aesdec_si128()      // Decryption round
_mm_aesdeclast_si128()  // Final decryption round
_mm_aesimc_si128()      // Inverse MixColumns
```

Compile with `-maes` flag to enable AES-NI instructions.

## Testing

```bash
# Run test suite
make test
./tests/test_taes

# Test encrypt/decrypt reversibility
echo "Hello, World!" | ./encrypt 128 pass1 pass2 | ./decrypt 128 pass1 pass2

# Test with random binary data
dd if=/dev/urandom bs=1M count=10 | ./encrypt 256 key1 key2 | ./decrypt 256 key1 key2 > output
```

## Performance Results

*To be completed after implementation*

Expected performance comparison:

- T-AES overhead vs standard AES
- T-AES counter mode vs XTS
- AES-NI speedup factor

## Security Considerations

⚠️ **Educational Purpose Only**

This implementation is for educational purposes and has **NOT** been audited for security. Do not use in production systems.

**Known Considerations:**

- Key derivation from passwords is simplified (not production-grade)
- Timing attacks not specifically mitigated
- Side-channel resistance not evaluated
- T-AES is a custom construction (not standardized)

## References

1. [Intel AES-NI White Paper](https://www.intel.com/content/dam/develop/external/us/en/documents/aes-wp-2012-09-22-v01-165683.pdf)
2. [NIST FIPS 197: AES Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
3. [Ciphertext Stealing - Wikipedia](https://en.wikipedia.org/wiki/Ciphertext_stealing)

## License

This project is submitted as coursework for the Cybersecurity MSc program at [University Name], 2025-26.

## Author

Rúben Lopes  
Cybersecurity MSc  
Applied Cryptography Course

## Acknowledgments

- Course instructors for project specification
- OpenSSL/Nettle library developers
- Intel for AES-NI documentation

---

**Due Date:** November 9, 2025  
**Course:** Applied Cryptography 2025-26  
**Project:** 1st Project - Tweakable AES
