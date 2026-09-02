#!/usr/bin/env bash
# Build the mobile artefacts this crate distributes.
#
# The crate owns its own packaging: a consumer needs the `dist/` directory this
# produces and nothing else — no cargo, no Rust toolchain, no NDK, and no
# knowledge of which cargo target triple maps to which device. Previously the
# consuming app cross-compiled the crate itself, which put a linker path and an
# NDK search inside a Gradle build that has no business knowing either.
#
#   dist/include/kms_mobile.h                            the C ABI, verbatim
#   dist/android/jniLibs/<abi>/libkms_mobile.so          drop into an APK as-is
#   dist/ios/KmsMobile.xcframework                       device + simulator slices
#   dist/BUILD-INFO.txt                                  what produced them
#
# Usage: ./build-mobile.sh [all|android|ios]
#        ANDROID_ABIS="arm64-v8a x86_64" ./build-mobile.sh android
set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$crate_dir/../.." && pwd)"
dist="$crate_dir/dist"
package="krusty-kms-mobile-cabi"
lib="libkms_mobile"

# Android ABIs, named as the jniLibs directories they become. arm64-v8a by
# default and on its own:
# there is no x86_64 Android *phone* to serve — that was Intel's Atom era, a
# decade below the API 37 this app requires — and an Apple-silicon host runs an
# arm64 emulator.
#
# x86_64 exists for the case that is not a phone: an emulator on an Intel or
# Windows/Linux host, and CI runners, which are x86_64 almost everywhere
# (GitHub-hosted included). An arm64 emulator on an x86_64 runner is software
# emulation and far too slow for an instrumented test, so that lane needs this:
#
#   ANDROID_ABIS="arm64-v8a x86_64" ./build-mobile.sh android
#
# It is opt-in rather than default because it costs every builder a second rust
# target install for an artefact almost none of them will load.
android_abis=(${ANDROID_ABIS:-arm64-v8a})
android_triple_for() {
  case "$1" in
  arm64-v8a) echo "aarch64-linux-android" ;;
  x86_64) echo "x86_64-linux-android" ;;
  armeabi-v7a) echo "armv7-linux-androideabi" ;;
  x86) echo "i686-linux-android" ;;
  *)
    echo "error: unknown Android ABI '$1'" >&2
    exit 1
    ;;
  esac
}
# The NDK API level the library is linked against — its floor, not the app's.
# Kept below minSdk so this artefact is not the thing that decides it.
android_api="${ANDROID_API_LEVEL:-31}"

ios_targets=("aarch64-apple-ios" "aarch64-apple-ios-sim")

what="${1:-all}"
case "$what" in
all | android | ios) ;;
*)
  echo "usage: $(basename "$0") [all|android|ios]" >&2
  exit 2
  ;;
esac

require_target() {
  # rustup is asked rather than assumed: a missing std for the triple fails deep
  # inside cargo with an error about a missing core, which reads like a code bug.
  if ! rustup target list --installed | grep -qx "$1"; then
    echo "error: rust target $1 is not installed. Run: rustup target add $1" >&2
    exit 1
  fi
}

# The NDK ships the only linker that can produce an Android shared object.
# Newest wins; failing loudly beats linking against whatever is first.
find_ndk() {
  if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
    echo "$ANDROID_NDK_HOME"
    return
  fi
  local sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
  local newest
  newest="$(find "$sdk/ndk" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort -V | tail -1)"
  if [[ -z "$newest" ]]; then
    echo "error: no Android NDK found under $sdk/ndk; set ANDROID_NDK_HOME" >&2
    exit 1
  fi
  echo "$newest"
}

build_android() {
  local ndk host
  ndk="$(find_ndk)"
  case "$(uname -s)" in
  Darwin) host="darwin-x86_64" ;;
  Linux) host="linux-x86_64" ;;
  *)
    echo "error: unsupported host $(uname -s) for the Android NDK toolchain" >&2
    exit 1
    ;;
  esac

  # Cleared first: a dropped ABI would otherwise leave its old library behind,
  # and a consumer that reads this directory to decide what to package would keep
  # shipping it -- stale, and for hardware nobody asked to support any more.
  rm -rf "$dist/android/jniLibs"

  local abi triple clang linker_var
  for abi in "${android_abis[@]}"; do
    triple="$(android_triple_for "$abi")"
    require_target "$triple"
    # The NDK names its clang wrappers after the *triple*, and armv7's wrapper
    # drops the "eabi" the rust triple carries.
    clang="$ndk/toolchains/llvm/prebuilt/$host/bin/${triple%eabi}${android_api}-clang"
    if [[ ! -x "$clang" ]]; then
      echo "error: no NDK clang at $clang (API $android_api); set ANDROID_API_LEVEL" >&2
      exit 1
    fi
    # cargo reads the linker from a per-target variable, so it is spelled from
    # the triple rather than hardcoded: SCREAMING_SNAKE, hyphens to underscores.
    linker_var="CARGO_TARGET_$(echo "$triple" | tr 'a-z-' 'A-Z_')_LINKER"

    echo "==> android: $abi / $triple (API $android_api)"
    env "$linker_var=$clang" \
      cargo build --release --manifest-path "$root/Cargo.toml" -p "$package" --target "$triple"

    mkdir -p "$dist/android/jniLibs/$abi"
    cp "$root/target/$triple/release/$lib.so" "$dist/android/jniLibs/$abi/"
  done
}

build_ios() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: the XCFramework needs xcodebuild, which is macOS-only" >&2
    exit 1
  fi
  local args=()
  for target in "${ios_targets[@]}"; do
    require_target "$target"
    echo "==> ios: $target"
    cargo build --release --manifest-path "$root/Cargo.toml" -p "$package" --target "$target"
  done

  # One staged header directory, shared by both slices. The modulemap is
  # generated here rather than kept in include/: cinterop reads that directory
  # with a headerFilter, and a stray module map there is one more thing that
  # could shadow the header it is meant to describe.
  local headers="$dist/ios/Headers"
  rm -rf "$headers"
  mkdir -p "$headers"
  cp "$crate_dir/include/kms_mobile.h" "$headers/"
  cat >"$headers/module.modulemap" <<'MODULEMAP'
module KmsMobile {
    header "kms_mobile.h"
    export *
}
MODULEMAP

  for target in "${ios_targets[@]}"; do
    args+=(-library "$root/target/$target/release/$lib.a" -headers "$headers")
  done
  # Rebuilt from scratch: create-xcframework refuses to overwrite, and a merged
  # leftover slice from an older run is exactly the artefact nobody would notice.
  rm -rf "$dist/ios/KmsMobile.xcframework"
  xcodebuild -create-xcframework "${args[@]}" -output "$dist/ios/KmsMobile.xcframework" >/dev/null
  rm -rf "$headers"
}

mkdir -p "$dist/include"
cp "$crate_dir/include/kms_mobile.h" "$dist/include/"

[[ "$what" == "all" || "$what" == "android" ]] && build_android
[[ "$what" == "all" || "$what" == "ios" ]] && build_ios

# Which krusty built these. A consumer holding only `dist/` has no other way to
# tell, and "the .so is older than the header" is the failure this answers.
{
  echo "package: $package"
  echo "version: $(cargo metadata --no-deps --format-version 1 --manifest-path "$root/Cargo.toml" |
    sed -n 's/.*"name":"'"$package"'","version":"\([^"]*\)".*/\1/p' | head -1)"
  echo "git: $(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)$(git -C "$root" diff --quiet 2>/dev/null || echo "-dirty")"
  echo "built: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host: $(uname -sm)"
  echo "scope: $what"
  echo "android-abis: ${android_abis[*]}"
} >"$dist/BUILD-INFO.txt"

echo "==> artefacts in $dist"
find "$dist" -maxdepth 3 -mindepth 1 -not -path "*/KmsMobile.xcframework/*" | sed "s|$dist|dist|"
