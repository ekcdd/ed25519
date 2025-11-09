//
// export.h
//
// This header defines the ED25519_DECLSPEC macro used to control
// symbol visibility when building or using the Ed25519 library
// as a shared library (DLL on Windows, .so on Linux).
//
// Usage:
//   - When building as a shared library (CMake option ED25519_BUILD_SHARED=ON):
//       * On Windows, symbols are exported using __declspec(dllexport).
//       * On non-Windows platforms, symbols use default visibility.
//   - When using the shared library in another project, define ED25519_DLL
//     (or let CMake do it automatically) to import the symbols.
//   - When building statically, this macro resolves to nothing.
//

#ifndef ED25519_EXPORT_H
#define ED25519_EXPORT_H

#if defined(_WIN32)
    #if defined(ED25519_BUILD_DLL)
        #define ED25519_DECLSPEC __declspec(dllexport)
    #elif defined(ED25519_DLL)
        #define ED25519_DECLSPEC __declspec(dllimport)
    #else
        #define ED25519_DECLSPEC
    #endif
#else
    #define ED25519_DECLSPEC
#endif

#endif //ED25519_EXPORT_H
