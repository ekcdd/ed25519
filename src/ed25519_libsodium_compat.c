#include <string.h>

#include "ed25519_libsodium_compat.h"
#include "ed25519.h"

#ifdef ED25519_LIBSODIUM_COMPAT_IMPL

/* Basic compile-time sanity checks against expected sizes */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(ED25519_LIBSODIUM_SEED_LEN == 32, "Seed length must be 32");
_Static_assert(ED25519_LIBSODIUM_PUBLIC_KEY_LEN == 32, "Public key length must be 32");
_Static_assert(ED25519_LIBSODIUM_SECRET_KEY_LEN == 64, "Secret key length must be 64");
_Static_assert(ED25519_LIBSODIUM_SIGNATURE_LEN == 64, "Signature length must be 64");
#endif

int ed25519_libsodium_to_orlp_secret_key(
    unsigned char *orlp_private_key,
    const unsigned char *libsodium_secret_key)
{
    if (!orlp_private_key || !libsodium_secret_key) {
        return ED25519_LIBSODIUM_ERR_INVALID_ARG;
    }

    /* Extract seed from libsodium format (first 32 bytes) */
    const unsigned char *seed = libsodium_secret_key;

    /* Recreate orlp private key from seed; ed25519_create_keypair requires a non-null public_key */
    unsigned char dummy_public_key[ED25519_LIBSODIUM_PUBLIC_KEY_LEN];
    ed25519_create_keypair(dummy_public_key, orlp_private_key, seed);

    return ED25519_LIBSODIUM_OK;
}

int ed25519_orlp_to_libsodium_secret_key(
    const unsigned char *libsodium_secret_key,
    const unsigned char *orlp_private_key,
    const unsigned char *public_key)
{
    (void)libsodium_secret_key;
    (void)orlp_private_key;
    (void)public_key;

    /*
     * Note: orlp doesn't expose the seed from private_key directly.
     * You must track the seed separately when converting back.
     * This function requires the seed to be reconstructed externally.
     */

    /* Not implementable without the original seed */
    return ED25519_LIBSODIUM_ERR_NOT_IMPLEMENTED;
}

int ed25519_create_keypair_libsodium(
    unsigned char *libsodium_public_key,
    unsigned char *libsodium_secret_key)
{
    unsigned char seed[ED25519_LIBSODIUM_SEED_LEN];
    unsigned char orlp_private_key[64];

    if (!libsodium_public_key || !libsodium_secret_key) {
        return ED25519_LIBSODIUM_ERR_INVALID_ARG;
    }

    /* Create random seed */
    if (ed25519_create_seed(seed)) {
        return ED25519_LIBSODIUM_ERR_INVALID_ARG;
    }

    /* Create keypair using orlp */
    ed25519_create_keypair(libsodium_public_key, orlp_private_key, seed);

    /* Create libsodium format: seed || public_key */
    memcpy(libsodium_secret_key, seed, ED25519_LIBSODIUM_SEED_LEN);
    memcpy(libsodium_secret_key + ED25519_LIBSODIUM_SEED_LEN, libsodium_public_key, ED25519_LIBSODIUM_PUBLIC_KEY_LEN);

    return ED25519_LIBSODIUM_OK;
}

int ed25519_sign_libsodium(
    unsigned char *signature,
    const unsigned char *message,
    const size_t message_len,
    const unsigned char *libsodium_secret_key)
{
    unsigned char orlp_private_key[64];
    unsigned char reconstructed_public_key[ED25519_LIBSODIUM_PUBLIC_KEY_LEN];
    const unsigned char *seed = libsodium_secret_key;
    const unsigned char *public_key = libsodium_secret_key + ED25519_LIBSODIUM_SEED_LEN;

    if (!signature || !message || !libsodium_secret_key) {
        return ED25519_LIBSODIUM_ERR_INVALID_ARG;
    }

    if (message_len == 0) {
        return ED25519_LIBSODIUM_ERR_INVALID_ARG;
    }

    /* Reconstruct orlp private key from seed; provide a non-null public_key buffer */
    ed25519_create_keypair(reconstructed_public_key, orlp_private_key, seed);

    /* Sign using orlp function (use public_key from libsodium_secret_key for clarity) */
    ed25519_sign(signature, message, message_len, public_key, orlp_private_key);

    return ED25519_LIBSODIUM_OK;
}

int ed25519_verify_libsodium(
    const unsigned char *signature,
    const unsigned char *message,
    const size_t message_len,
    const unsigned char *public_key)
{
    /* Direct wrapper - verification is same in both libraries */
    return ed25519_verify(signature, message, message_len, public_key);
}

int ed25519_public_key_from_libsodium_secret(
    unsigned char *public_key,
    const unsigned char *libsodium_secret_key)
{
    if (!public_key || !libsodium_secret_key) {
        return ED25519_LIBSODIUM_ERR_INVALID_ARG;
    }

    /* libsodium format: secret_key = seed(32) || public_key(32) */
    memcpy(public_key,
           libsodium_secret_key + ED25519_LIBSODIUM_SEED_LEN,
           ED25519_LIBSODIUM_PUBLIC_KEY_LEN);

    return ED25519_LIBSODIUM_OK;
}

#endif /* ED25519_LIBSODIUM_COMPAT_IMPL */