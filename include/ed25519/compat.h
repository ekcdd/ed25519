//
// libsodium_compat.h (public)
//
// Compatibility layer between the orlp Ed25519 implementation and the
// libsodium API format. Public header intended for installation/consumption
// as <ed25519/ed25519_libsodium_compat.h>.
//
#ifndef ED25519_COMPAT_H
#define ED25519_COMPAT_H

#include <ed25519/export.h>

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

int ED25519_DECLSPEC ed25519_libsodium_to_orlp_secret_key(
    unsigned char *orlp_private_key,
    const unsigned char *libsodium_secret_key);

int ED25519_DECLSPEC ed25519_orlp_to_libsodium_secret_key(
    const unsigned char *libsodium_secret_key,
    const unsigned char *orlp_private_key,
    const unsigned char *public_key);

int ED25519_DECLSPEC ed25519_create_keypair_libsodium(
    unsigned char *libsodium_public_key,
    unsigned char *libsodium_secret_key);

int ED25519_DECLSPEC ed25519_sign_libsodium(
    unsigned char *signature,
    const unsigned char *message,
    size_t message_len,
    const unsigned char *libsodium_secret_key);

int ED25519_DECLSPEC ed25519_verify_libsodium(
    const unsigned char *signature,
    const unsigned char *message,
    size_t message_len,
    const unsigned char *public_key);

int ED25519_DECLSPEC ed25519_public_key_from_libsodium_secret(
    unsigned char *public_key,
    const unsigned char *libsodium_secret_key);

#ifdef __cplusplus
}
#endif

#endif /* ED25519_LIBSODIUM_COMPAT_H */
