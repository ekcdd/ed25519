#include "ed25519.h"

#ifndef ED25519_NO_SEED

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <stdio.h>
#endif

int ed25519_create_seed(unsigned char *seed) {
#ifdef _WIN32
    const NTSTATUS status = BCryptGenRandom (NULL, seed, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG); // Flags
    if (status != 0x00000000) // STATUS_SUCCESS
    {
        return 1;
    }
    return 0;
#else
    FILE *f = fopen("/dev/urandom", "rb");

    if (f == NULL) {
        return 1;
    }

    const size_t size = fread(seed, 1, 32, f);
    (void)size; // hack: make the compiler think that size is used.
    fclose(f);
#endif

    return 0;
}

#endif
