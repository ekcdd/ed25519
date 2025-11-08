//
// libsodium_compat.h
//
// This header provides a compatibility layer between the orlp Ed25519
// implementation and the libsodium API format. It defines constants and
// functions that allow using orlp-style Ed25519 keys and signatures in
// libsodium-compatible structures.
//
// Usage:
//   - Secret keys in libsodium format: seed(32) || public_key(32)
//   - Public keys and signatures have identical formats in both libraries.
//   - Functions return ED25519_LIBSODIUM_OK (0) on success, or a negative
//     value on error.
//
// All functions are decorated with ED25519_DECLSPEC for cross-platform
// visibility control when building or using shared libraries.
//

#ifndef ED25519_LIBSODIUM_COMPAT_H
#define ED25519_LIBSODIUM_COMPAT_H

#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* libsodium format constants */
#define ED25519_LIBSODIUM_SECRET_KEY_LEN 64  /* seed(32) || public_key(32) */
#define ED25519_LIBSODIUM_PUBLIC_KEY_LEN 32
#define ED25519_LIBSODIUM_SEED_LEN 32
#define ED25519_LIBSODIUM_SIGNATURE_LEN 64

/* generic status codes for this compat layer */
#define ED25519_LIBSODIUM_OK 0
#define ED25519_LIBSODIUM_ERR_INVALID_ARG (-1)
#define ED25519_LIBSODIUM_ERR_NOT_IMPLEMENTED (-2)

/*
 * Convert from libsodium secret key format to orlp private key format.
 *
 * libsodium_secret_key: 64 bytes (seed || public_key)
 * orlp_private_key: 64 bytes (internal orlp representation) [output]
 *
 * Returns ED25519_LIBSODIUM_OK (0) on success, negative on error.
 */
int ED25519_DECLSPEC ed25519_libsodium_to_orlp_secret_key(
    unsigned char *orlp_private_key,
    const unsigned char *libsodium_secret_key);

/*
 * Convert from orlp private key format to libsodium secret key format.
 *
 * IMPORTANT: The orlp API does not expose the original 32-byte seed, so
 * reconstruction of the libsodium secret key (seed || public_key) is not
 * generally possible unless the caller provides the seed out-of-band.
 *
 * libsodium_secret_key: 64 bytes (output: seed || public_key)
 * orlp_private_key: 64 bytes (input)
 * public_key: 32 bytes (input)
 *
 * Returns ED25519_LIBSODIUM_ERR_NOT_IMPLEMENTED (-2) to indicate the one-way
 * limitation of the upstream API.
 */
int ED25519_DECLSPEC ed25519_orlp_to_libsodium_secret_key(
    const unsigned char *libsodium_secret_key,
    const unsigned char *orlp_private_key,
    const unsigned char *public_key);

/*
 * Create a keypair in libsodium format (secret_key = seed || public_key).
 *
 * libsodium_public_key: 32 bytes (output)
 * libsodium_secret_key: 64 bytes (output)
 *
 * Returns ED25519_LIBSODIUM_OK (0) on success, negative on error.
 */
int ED25519_DECLSPEC ed25519_create_keypair_libsodium(
    unsigned char *libsodium_public_key,
    unsigned char *libsodium_secret_key);

/*
 * Sign a message using a libsodium-format secret key.
 *
 * signature: 64 bytes (output)
 * message: pointer to message to sign
 * message_len: length of message
 * libsodium_secret_key: 64 bytes in libsodium format (seed || public_key)
 *
 * Returns ED25519_LIBSODIUM_OK (0) on success, negative on error.
 */
int ED25519_DECLSPEC ed25519_sign_libsodium(
    unsigned char *signature,
    const unsigned char *message,
    size_t message_len,
    const unsigned char *libsodium_secret_key);

/*
 * Verify a signature using the public key (same format in both libraries).
 *
 * Wrapper for ed25519_verify with libsodium-like naming.
 *
 * Returns 1 if signature is valid, 0 otherwise.
 */
int ED25519_DECLSPEC ed25519_verify_libsodium(
    const unsigned char *signature,
    const unsigned char *message,
    size_t message_len,
    const unsigned char *public_key);

/*
 * Extract the public key from a libsodium-format secret key.
 *
 * libsodium_secret_key: 64 bytes (seed || public_key)
 * public_key: 32 bytes (output)
 *
 * Returns ED25519_LIBSODIUM_OK (0) on success, negative on error.
 */
int ED25519_DECLSPEC ed25519_public_key_from_libsodium_secret(
    unsigned char *public_key,
    const unsigned char *libsodium_secret_key);

#ifdef __cplusplus
}
#endif

#endif /* ED25519_LIBSODIUM_COMPAT_H */
