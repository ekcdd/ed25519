cmake_minimum_required(VERSION 3.10)
project(ed25519 VERSION 1.0 LANGUAGES C CXX)


set(CMAKE_C_STANDARD 11)

# ==== Options ====
option(ED25519_BUILD_SHARED "Build ed25519 as a shared library (DLL/.so)" OFF)
option(ED25519_NO_SEED "Disable ed25519_create_seed and exclude OS RNG usage" OFF)
option(ED25519_USE_ASAN "Enable AddressSanitizer for debug builds" OFF)

# ==== Detect libsodium ====
set(SODIUM_AVAILABLE FALSE)
find_package(PkgConfig QUIET)

if(PkgConfig_FOUND)
    pkg_check_modules(SODIUM libsodium)
    if(SODIUM_FOUND)
        set(SODIUM_AVAILABLE TRUE)
    else()
        message(WARNING "libsodium not found via pkg-config. 'sodiumtest' will be skipped.")
    endif()
else()
    message(STATUS "pkg-config not found, trying manual libsodium search...")
    find_library(SODIUM_LIBRARY NAMES sodium)
    find_path(SODIUM_INCLUDE_DIR NAMES sodium.h)
    if(SODIUM_LIBRARY AND SODIUM_INCLUDE_DIR)
        set(SODIUM_AVAILABLE TRUE)
    else()
        message(WARNING "libsodium not found. 'sodiumtest' will be skipped. Install libsodium-dev to enable it.")
    endif()
endif()

# ==== Source Files ====
set(ED25519_SOURCES
        src/add_scalar.c
        src/key_exchange.c
        src/keypair.c
        src/seed.c
        src/sha512.c
        src/sign.c
        src/verify.c
        src/ge.c
        src/fe.c
        src/sc.c
        src/compat.c
)

# ==== Library Target ====
if(ED25519_BUILD_SHARED)
    add_library(ed25519 SHARED ${ED25519_SOURCES})
    target_compile_definitions(ed25519 PRIVATE ED25519_BUILD_DLL)
    target_compile_definitions(ed25519 INTERFACE ED25519_DLL)
else()
    add_library(ed25519 STATIC ${ED25519_SOURCES})
endif()

set_target_properties(ed25519 PROPERTIES POSITION_INDEPENDENT_CODE ON)

# ==== Include Dirs & Defines ====
target_include_directories(ed25519 PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_definitions(ed25519 PUBLIC ED25519_LIBSODIUM_COMPAT_IMPL)

if(ED25519_NO_SEED)
    target_compile_definitions(ed25519 PUBLIC ED25519_NO_SEED)
endif()

# ==== Windows RNG linkage ====
if(WIN32 AND NOT ED25519_NO_SEED)
    target_link_libraries(ed25519 PUBLIC bcrypt)
endif()

# ==== Optional AddressSanitizer ====
if(ED25519_USE_ASAN AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "AddressSanitizer enabled for Debug builds.")
    set(ASAN_FLAGS "-fsanitize=address -fno-omit-frame-pointer")
    add_compile_options(${ASAN_FLAGS})
    add_link_options(${ASAN_FLAGS})
endif()

# ==== sodiumtest (optional) ====
if(SODIUM_AVAILABLE AND NOT ED25519_NO_SEED)
    add_executable(sodiumtest tests/sodiumtest.c)
    target_include_directories(sodiumtest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/include)
    if(SODIUM_FOUND)
        target_link_libraries(sodiumtest PRIVATE ed25519 ${SODIUM_LIBRARIES})
        target_include_directories(sodiumtest PRIVATE ${SODIUM_INCLUDE_DIRS})
    else()
        target_link_libraries(sodiumtest PRIVATE ed25519 ${SODIUM_LIBRARY})
        target_include_directories(sodiumtest PRIVATE ${SODIUM_INCLUDE_DIR})
    endif()
elseif(SODIUM_AVAILABLE AND ED25519_NO_SEED)
    message(STATUS "Skipping 'sodiumtest' because ED25519_NO_SEED is ON.")
else()
    message(STATUS "Skipping 'sodiumtest' because libsodium was not found.")
endif()

# ==== Benchmark / Demo ====
if(NOT ED25519_NO_SEED)
    add_executable(ed25519_bench tests/test.c)
    target_link_libraries(ed25519_bench PRIVATE ed25519)
    target_include_directories(ed25519_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/include)
else()
    message(STATUS "Skipping 'ed25519_bench' because ED25519_NO_SEED is ON.")
endif()
