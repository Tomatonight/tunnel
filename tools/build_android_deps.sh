#!/usr/bin/env bash
set -euo pipefail
# Run under Linux with the Linux NDK. Inputs are unpacked upstream sources.
: "${ANDROID_NDK_ROOT:?Set ANDROID_NDK_ROOT}"
: "${OPENSSL_SOURCE:?Set OPENSSL_SOURCE to an unpacked OpenSSL 3.x source tree}"
: "${LIBEVENT_SOURCE:?Set LIBEVENT_SOURCE to an unpacked libevent source tree}"
output=$(realpath -m "${1:-android-deps}")
openssl_source=$(realpath "$OPENSSL_SOURCE")
libevent_source=$(realpath "$LIBEVENT_SOURCE")
ndk_root=$(realpath "$ANDROID_NDK_ROOT")
export ANDROID_NDK_ROOT="$ndk_root"
export PATH="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
for abi in arm64-v8a x86_64; do
    prefix="$output/$abi"
    build="$output/build-$abi"
    mkdir -p "$prefix" "$build/openssl"
    if [[ "$abi" == arm64-v8a ]]; then target=android-arm64; else target=android-x86_64; fi
    (
        cd "$build/openssl"
        perl "$openssl_source/Configure" "$target" -D__ANDROID_API__=26 no-shared no-tests -fPIC \
            --prefix="$prefix" --libdir=lib
        make -j2
        make install_sw
    )
    cmake -S "$libevent_source" -B "$build/libevent" \
        -DCMAKE_TOOLCHAIN_FILE="$ndk_root/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI="$abi" -DANDROID_PLATFORM=android-26 -DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON \
        -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DEVENT__DISABLE_OPENSSL=ON -DEVENT__DISABLE_TESTS=ON -DEVENT__DISABLE_REGRESS=ON \
        -DEVENT__DISABLE_SAMPLES=ON -DEVENT__LIBRARY_TYPE=STATIC
    cmake --build "$build/libevent" --parallel 2
    cmake --install "$build/libevent"
done
