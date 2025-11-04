#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "ed25519.h"
#include "ed25519_libsodium_compat.h"


int main() {
    unsigned char public_key[32], private_key[64], seed[32], scalar[32];
    unsigned char other_public_key[32], other_private_key[64];
    unsigned char shared_secret[32], other_shared_secret[32];
    unsigned char signature[64];

    int i;

    const unsigned char message[] = "Hello, world!";
    const int message_len = (int)strlen((char*) message);

    /* create a random seed, and a keypair out of that seed */
    ed25519_create_seed(seed);
    ed25519_create_keypair(public_key, private_key, seed);

    /* create signature on the message with the keypair */
    ed25519_sign(signature, message, message_len, public_key, private_key);

    /* verify the signature */
    if (ed25519_verify(signature, message, message_len, public_key)) {
        printf("valid signature\n");
    } else {
        printf("invalid signature\n");
    }

    /* ---- libsodium compat API tests ---- */
    unsigned char ls_public_key[ED25519_LIBSODIUM_PUBLIC_KEY_LEN];
    unsigned char ls_secret_key[ED25519_LIBSODIUM_SECRET_KEY_LEN];
    unsigned char ls_signature[ED25519_LIBSODIUM_SIGNATURE_LEN];
    unsigned char orlp_private_from_ls[64];

    /* create a libsodium-format keypair (secret = seed || pk) */
    if (ed25519_create_keypair_libsodium(ls_public_key, ls_secret_key) == ED25519_LIBSODIUM_OK) {
        printf("created libsodium-format keypair\n");
    } else {
        printf("failed to create libsodium-format keypair\n");
    }

    /* sign using libsodium-format secret key */
    if (ed25519_sign_libsodium(ls_signature, message, (size_t)message_len, ls_secret_key) == ED25519_LIBSODIUM_OK) {
        printf("created signature with libsodium compat api\n");
    } else {
        printf("failed to create signature with libsodium compat api\n");
    }

    /* verify via compat wrapper (same as ed25519_verify) */
    if (ed25519_verify_libsodium(ls_signature, message, (size_t)message_len, ls_public_key)) {
        printf("valid signature (compat verify)\n");
    } else {
        printf("invalid signature (compat verify)\n");
    }

    /* cross-verify using original API as well */
    if (ed25519_verify(ls_signature, message, message_len, ls_public_key)) {
        printf("valid signature (orlp verify on compat-signed)\n");
    } else {
        printf("invalid signature (orlp verify on compat-signed)\n");
    }

    /* convert libsodium secret key back to orlp private key and sign; signatures should match */
    if (ed25519_libsodium_to_orlp_secret_key(orlp_private_from_ls, ls_secret_key) == ED25519_LIBSODIUM_OK) {
        unsigned char sig2[64];
        const unsigned char *pk_from_sk = ls_secret_key + ED25519_LIBSODIUM_SEED_LEN; /* second half is public key */
        ed25519_sign(sig2, message, message_len, pk_from_sk, orlp_private_from_ls);
        if (memcmp(sig2, ls_signature, 64) == 0) {
            printf("compat/orlp signatures match for same message and key\n");
        } else {
            printf("compat/orlp signatures differ (still should verify)\n");
        }
        if (ed25519_verify(sig2, message, message_len, pk_from_sk)) {
            printf("valid signature (orlp sign from converted key)\n");
        } else {
            printf("invalid signature (orlp sign from converted key)\n");
        }
    } else {
        printf("failed to convert libsodium secret key to orlp private key\n");
    }

    /* negative test: flip a bit and expect verification to fail via compat verify */
    ls_signature[10] ^= 0x01;
    if (ed25519_verify_libsodium(ls_signature, message, (size_t)message_len, ls_public_key)) {
        printf("did not detect signature change (compat)\n");
    } else {
        printf("correctly detected signature change (compat)\n");
    }
    /* restore byte for subsequent tests */
    ls_signature[10] ^= 0x01;

    /* create scalar and add it to the keypair */
    ed25519_create_seed(scalar);
    ed25519_add_scalar(public_key, private_key, scalar);

    /* create signature with the new keypair */
    ed25519_sign(signature, message, message_len, public_key, private_key);

    /* verify the signature with the new keypair */
    if (ed25519_verify(signature, message, message_len, public_key)) {
        printf("valid signature\n");
    } else {
        printf("invalid signature\n");
    }

    /* make a slight adjustment and verify again */
    signature[44] ^= 0x10;
    if (ed25519_verify(signature, message, message_len, public_key)) {
        printf("did not detect signature change\n");
    } else {
        printf("correctly detected signature change\n");
    }

    /* generate two keypairs for testing key exchange */
    ed25519_create_seed(seed);
    ed25519_create_keypair(public_key, private_key, seed);
    ed25519_create_seed(seed);
    ed25519_create_keypair(other_public_key, other_private_key, seed);

    /* create two shared secrets - from both perspectives - and check if they're equal */
    ed25519_key_exchange(shared_secret, other_public_key, private_key);
    ed25519_key_exchange(other_shared_secret, public_key, other_private_key);

    for (i = 0; i < 32; ++i) {
        if (shared_secret[i] != other_shared_secret[i]) {
            printf("key exchange was incorrect\n");
            break;
        }
    }

    if (i == 32) {
        printf("key exchange was correct\n");
    }

    /* test performance */
    printf("testing seed generation performance: ");
    clock_t start = clock();
    for (i = 0; i < 10000; ++i) {
        ed25519_create_seed(seed);
    }
    clock_t end = clock();

    printf("%fus per seed\n", ((double) ((end - start) * 1000)) / CLOCKS_PER_SEC / i * 1000);


    printf("testing key generation performance: ");
    start = clock();
    for (i = 0; i < 10000; ++i) {
        ed25519_create_keypair(public_key, private_key, seed);
    }
    end = clock();

    printf("%fus per keypair\n", ((double) ((end - start) * 1000)) / CLOCKS_PER_SEC / i * 1000);

    printf("testing sign performance: ");
    start = clock();
    for (i = 0; i < 10000; ++i) {
        ed25519_sign(signature, message, message_len, public_key, private_key);
    }
    end = clock();

    printf("%fus per signature\n", ((double) ((end - start) * 1000)) / CLOCKS_PER_SEC / i * 1000);

    printf("testing verify performance: ");
    start = clock();
    for (i = 0; i < 10000; ++i) {
        ed25519_verify(signature, message, message_len, public_key);
    }
    end = clock();

    printf("%fus per signature\n", ((double) ((end - start) * 1000)) / CLOCKS_PER_SEC / i * 1000);


    printf("testing keypair scalar addition performance: ");
    start = clock();
    for (i = 0; i < 10000; ++i) {
        ed25519_add_scalar(public_key, private_key, scalar);
    }
    end = clock();

    printf("%fus per keypair\n", ((double) ((end - start) * 1000)) / CLOCKS_PER_SEC / i * 1000);

    printf("testing public key scalar addition performance: ");
    start = clock();
    for (i = 0; i < 10000; ++i) {
        ed25519_add_scalar(public_key, NULL, scalar);
    }
    end = clock();

    printf("%fus per key\n", ((double) ((end - start) * 1000)) / CLOCKS_PER_SEC / i * 1000);

    printf("testing key exchange performance: ");
    start = clock();
    for (i = 0; i < 10000; ++i) {
        ed25519_key_exchange(shared_secret, other_public_key, private_key);
    }
    end = clock();

    printf("%fus per shared secret\n", ((double) ((end - start) * 1000)) / CLOCKS_PER_SEC / i * 1000);

    return 0;
}