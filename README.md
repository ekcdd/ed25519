# Ed25519 (with libsodium compatibility)

This repository provides a portable implementation of Ed25519 based on the SUPERCOP "ref10" code (the well‑known orlp/ed25519 variant), plus a thin compatibility layer that lets you use keys in the same on‑disk/in‑memory format as libsodium and produce byte‑for‑byte identical signatures for the same inputs.

All code is ANSI C with no third‑party dependencies for core Ed25519 operations. An interoperability test suite and a small benchmark/demo app are included.

## What's included

- **Pure Ed25519:** key generation, signing, verification
- **Extras:** scalar addition and X25519‑style key exchange helpers (as in the original orlp library)
- **Libsodium compatibility layer** (src/ed25519_libsodium_compat.[ch]):
  - Creates keypairs in libsodium secret key layout: seed (32) || public_key (32)
  - Signs messages using libsodium‑format secret keys
  - Verifies signatures using the standard 32‑byte public key
  - Produces keys and signatures that are byte‑for‑byte identical to libsodium for the same seed/message
- **Test suite** (sodiumtest): Verifies equality and cross‑verification against libsodium
- **Benchmark/demo app** (ed25519_bench): Based on the classic test.c

## Quick Start

Here's a minimal example using the libsodium‑compatible API:

```c
#include <ed25519/ed25519.h>

unsigned char pk[32], sk[64];
unsigned char message[] = "Hello, World!";
unsigned char signature[64];

// Generate a keypair
if (ed25519_create_keypair_libsodium(pk, sk) != ED25519_LIBSODIUM_OK) {
    fprintf(stderr, "Failed to create keypair\n");
    return 1;
}

// Sign a message
if (ed25519_sign_libsodium(signature, message, sizeof(message) - 1, sk) != ED25519_LIBSODIUM_OK) {
    fprintf(stderr, "Failed to sign message\n");
    return 1;
}

// Verify the signature
if (ed25519_verify_libsodium(signature, message, sizeof(message) - 1, pk) == 0) {
    printf("Signature valid!\n");
} else {
    printf("Signature invalid!\n");
}
```

**Choosing an API:** If you're integrating with libsodium or need compatibility with its key format, use the libsodium‑compat API (see below). Otherwise, use the native orlp API for direct control.

## Build

### Requirements

- A C toolchain (C11 or later)
- CMake 3.12+
- **Optional:** libsodium development headers and library (required only to build and run `sodiumtest`; e.g., `sudo apt-get install libsodium-dev` on Debian/Ubuntu)

### Platform-Specific Notes

The core library is **dependency‑free** if you disable seed generation. Seed generation (enabled by default) uses standard OS random number generators:

- **Windows:** BCryptGenRandom (part of Windows CNG; requires bcrypt library linking)
- **Unix-like:** /dev/urandom (no external dependency)
- **Completely self-contained:** Use `-DED25519_NO_SEED=ON` to disable seed generation entirely. This removes the OS RNG dependency and avoids bcrypt linking. You must then provide your own 32‑byte cryptographically secure seed.

### Targets

- `ed25519` — static library (or shared, see option below)
- `sodiumtest` — interoperability and equality test suite (built only if libsodium is found)
- `ed25519_bench` — small demo/benchmark based on the classic test.c

### Build Example

```bash
# Configure (choose a build directory)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

# Build all targets
cmake --build build

# Or build specific targets
cmake --build build --target ed25519 ed25519_bench
```

### Verify the Build

If libsodium was found and `sodiumtest` was built:

```bash
./build/sodiumtest
```

Expected output: all tests passed.

Run the benchmark:

```bash
./build/ed25519_bench
```

Expected output: operation timings (seed generation, signing, verification, etc.).

### Build Options

- `-DCMAKE_BUILD_TYPE=Release` (or Debug) — Optimize or keep debug symbols. Debug builds enable AddressSanitizer.
- `-DED25519_BUILD_SHARED=ON` — Build a shared library (DLL on Windows, .so on Unix) instead of static. On Windows with seed generation enabled (default), this links against bcrypt; consumers will import symbols automatically via `ED25519_DECLSPEC`.
- `-DED25519_NO_SEED=ON` — Disable the built-in `ed25519_create_seed()` function and exclude OS RNG usage entirely. This removes the bcrypt dependency on Windows and allows a completely dependency-free library. You must provide your own 32‑byte cryptographically secure seed. Default is OFF (seed generation enabled).

### Troubleshooting

- **Warning about ED25519_LIBSODIUM_COMPAT_IMPL being redefined:** Remove the macro from the top‑level ed25519.h and keep the CMake definition only.
- **sodiumtest not built:** Ensure libsodium-dev is installed. CMake will skip it silently if libsodium is not found.

## API Reference

Choose one API based on your needs:

### Libsodium-Compatible API (Recommended for most users)

Include `ed25519/compat.h` (or the convenience umbrella header `ed25519.h`). This wrapper lets you use libsodium's key layout and naming while calling into the embedded orlp implementation.

**Constants:**

```c
ED25519_LIBSODIUM_SEED_LEN        = 32
ED25519_LIBSODIUM_PUBLIC_KEY_LEN  = 32
ED25519_LIBSODIUM_SECRET_KEY_LEN  = 64   // seed (32) || public_key (32)
ED25519_LIBSODIUM_SIGNATURE_LEN   = 64
```

**Return codes:**

```c
ED25519_LIBSODIUM_OK               = 0
ED25519_LIBSODIUM_ERR_INVALID_ARG  = -1
ED25519_LIBSODIUM_ERR_NOT_IMPLEMENTED = -2
```

**Functions:**

```c
int ed25519_create_keypair_libsodium(unsigned char *libsodium_public_key,
                                     unsigned char *libsodium_secret_key);
```
Generates a new keypair. The secret key is formatted as seed (32 bytes) || public_key (32 bytes).

```c
int ed25519_sign_libsodium(unsigned char *signature,
                           const unsigned char *message, size_t message_len,
                           const unsigned char *libsodium_secret_key);
```
Signs a message with the libsodium-format secret key. Produces signatures identical to libsodium's `crypto_sign_detached`.

```c
int ed25519_verify_libsodium(const unsigned char *signature,
                             const unsigned char *message, size_t message_len,
                             const unsigned char *public_key);
```
Verifies a detached signature. Returns 0 on success, -1 on verification failure.

```c
int ed25519_libsodium_to_orlp_secret_key(unsigned char *orlp_private_key,
                                         const unsigned char *libsodium_secret_key);
```
Converts a libsodium secret key to orlp's 64‑byte internal private key format (requires no libsodium runtime).

```c
int ed25519_orlp_to_libsodium_secret_key(unsigned char *libsodium_secret_key,
                                         const unsigned char *orlp_private_key,
                                         const unsigned char *public_key);
```
Cannot reconstruct a libsodium secret key without the original 32‑byte seed (libsodium's upstream API doesn't expose it). Returns `ED25519_LIBSODIUM_ERR_NOT_IMPLEMENTED`. **If you need to store libsodium-format keys, keep the seed.**

### Native orlp API (For direct control)

Include `ed25519/ed25519.h`. **Important:** orlp's private_key is an internal 64‑byte structure, NOT the same layout as libsodium's 64‑byte secret key. Use the libsodium-compat API above if you need libsodium compatibility.

**Buffers:**

```c
unsigned char seed[32];           // cryptographically secure random seed
unsigned char signature[64];      // signature output
unsigned char public_key[32];     // public key
unsigned char private_key[64];    // orlp internal private key (not libsodium format!)
unsigned char scalar[32];         // for scalar operations
unsigned char shared_secret[32];  // for key exchange
```

**Functions:**

```c
int ed25519_create_seed(unsigned char *seed);
```
Generates a cryptographically secure 32-byte seed. Returns 0 on success, -1 on failure (e.g., if random generation is unavailable and ED25519_NO_SEED is defined).

```c
void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key,
                            const unsigned char *seed);
```
Generates a keypair from a seed.

```c
void ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len,
                  const unsigned char *public_key, const unsigned char *private_key);
```
Signs a message. The private_key must be the orlp-format 64‑byte structure from `ed25519_create_keypair`.

```c
int ed25519_verify(const unsigned char *signature, const unsigned char *message,
                   size_t message_len, const unsigned char *public_key);
```
Verifies a signature. Returns 0 on success, -1 on verification failure.

```c
void ed25519_add_scalar(unsigned char *public_key, unsigned char *private_key,
                        const unsigned char *scalar);
```
Adds a scalar to a keypair (useful for key derivation).

```c
void ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key,
                          const unsigned char *private_key);
```
Computes a shared secret using X25519-style key exchange.

## Compatibility Status

This implementation supports standard Ed25519 (RFC 8032) without context or prehashing. The included test suite asserts byte‑for‑byte identity with libsodium for plain Ed25519 (no context, no prehash) and detached signatures. This means you can migrate keys and signatures between this library and libsodium without any conversion—they're interchangeable.

Verification:

- Same seed → identical public keys (32 bytes)
- Same key + same message → identical signatures (64 bytes)
- Wrapper signatures match libsodium exactly
- Cross‑verification in both directions passes

**Limitations:** If you need Ed25519ph (prehashed) or Ed25519ctx, additional wrappers and tests would be required.

## Performance

Performance is similar to the original orlp/ed25519 implementation. On an older Intel Pentium B970 @ 2.3GHz (single core), typical timings were:

- Seed generation: ~64µs (15625/s)
- Key generation: ~88µs (11364/s)
- Signing (short message): ~87µs (11494/s)
- Verifying (short message): ~228µs (4386/s)
- Scalar addition: ~100µs (10000/s)
- Key exchange: ~220µs (4545/s)

Your results may vary; 64‑bit builds perform significantly better.

## License

All code is released under the permissive zlib license. See license.txt for details.