#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
core_build=${1:-"$root/build-wsl"}
output="$core_build/android-jni-tests"
mkdir -p "$output/classes"
task_jdk=${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")}
test -f "$task_jdk/include/jni.h"
test -f "$core_build/libtunnel_core.a"
g++ -std=c++11 -Wall -Wextra -Wpedantic -fPIC -shared -pthread \
    -I"$root" -I"$task_jdk/include" -I"$task_jdk/include/linux" \
    "$root/android/jni.cpp" "$core_build/libtunnel_core.a" \
    -lssl -lcrypto -levent_core -o "$output/libtunnel_android.so"
"$task_jdk/bin/javac" -encoding UTF-8 -d "$output/classes" \
    "$root/android/app/src/main/java/org/example/tunnel/NativeBridge.java" \
    "$root/android/tests/TunnelService.java" "$root/android/tests/ReloadBridgeTest.java"
"$task_jdk/bin/java" -Xcheck:jni -Djava.library.path="$output" -cp "$output/classes" org.example.tunnel.ReloadBridgeTest
