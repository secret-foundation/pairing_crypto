#!/usr/bin/env bash
set -euo pipefail

IOS_MIN_DEVICE=${IOS_MIN_DEVICE:-13.0}
IOS_MIN_SIM=${IOS_MIN_SIM:-13.0}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RN_PKG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUST_CRATE_DIR="$RN_PKG_ROOT/../../wrappers/c"
OBJC_HEADERS_DIR="$RN_PKG_ROOT/../../wrappers/obj-c/pairing_crypto"
TARGET_DIR="$RN_PKG_ROOT/../../target"

XCFRAMEWORK_PATH="$RN_PKG_ROOT/ios/PairingCrypto.xcframework"
SIM_FAT_DIR="$RN_PKG_ROOT/target/ios-sim-fat"
OBJC_DST_DIR="$RN_PKG_ROOT/ios/lib"

echo "==> Building pairing_crypto_c for iOS (device + simulators)"
echo "    Rust crate:   $RUST_CRATE_DIR"
echo "    Headers:      $OBJC_HEADERS_DIR"
echo "    Output XCFW:  $XCFRAMEWORK_PATH"
echo

rm -rf "$XCFRAMEWORK_PATH" "$SIM_FAT_DIR"
mkdir -p "$SIM_FAT_DIR" "$OBJC_DST_DIR" "$RN_PKG_ROOT/ios"

# Always clean to ensure BLST_PORTABLE takes effect
cargo clean -p pairing_crypto_c || true
cargo clean -p blst || true

echo "==> Device (arm64)"
echo
export SDKROOT="$(xcrun --sdk iphoneos --show-sdk-path)"
export CC="$(xcrun --sdk iphoneos -f clang)"
export AR="$(xcrun --sdk iphoneos -f ar)"
export IPHONEOS_DEPLOYMENT_TARGET="$IOS_MIN_DEVICE"
export BLST_PORTABLE=1
export CFLAGS="-fembed-bitcode -isysroot $SDKROOT -miphoneos-version-min=$IPHONEOS_DEPLOYMENT_TARGET"
export RUSTFLAGS="-C link-arg=-isysroot -C link-arg=$SDKROOT -C link-arg=-miphoneos-version-min=$IPHONEOS_DEPLOYMENT_TARGET"
cargo build -p pairing_crypto_c --manifest-path "$RUST_CRATE_DIR/Cargo.toml" --release --target aarch64-apple-ios

echo "==> Simulator (x86_64)"
echo
cargo clean -p pairing_crypto_c || true
cargo clean -p blst || true
export SDKROOT="$(xcrun --sdk iphonesimulator --show-sdk-path)"
export CC="$(xcrun --sdk iphonesimulator -f clang)"
export AR="$(xcrun --sdk iphonesimulator -f ar)"
export BLST_PORTABLE=1
export CFLAGS="-fembed-bitcode -isysroot $SDKROOT -mios-simulator-version-min=$IOS_MIN_SIM"
export RUSTFLAGS="-C link-arg=-isysroot -C link-arg=$SDKROOT -C link-arg=-mios-simulator-version-min=$IOS_MIN_SIM"
cargo build -p pairing_crypto_c --manifest-path "$RUST_CRATE_DIR/Cargo.toml" --release --target x86_64-apple-ios

echo "==> Simulator (arm64)"
echo
cargo clean -p pairing_crypto_c || true
cargo clean -p blst || true
export SDKROOT="$(xcrun --sdk iphonesimulator --show-sdk-path)"
export CC="$(xcrun --sdk iphonesimulator -f clang)"
export AR="$(xcrun --sdk iphonesimulator -f ar)"
export BLST_PORTABLE=1
export CFLAGS="-fembed-bitcode -isysroot $SDKROOT -mios-simulator-version-min=$IOS_MIN_SIM"
export RUSTFLAGS="-C link-arg=-isysroot -C link-arg=$SDKROOT -C link-arg=-mios-simulator-version-min=$IOS_MIN_SIM"
cargo build -p pairing_crypto_c --manifest-path "$RUST_CRATE_DIR/Cargo.toml" --release --target aarch64-apple-ios-sim

echo "==> Merging simulator slices"
echo
lipo -create \
  "$TARGET_DIR/aarch64-apple-ios-sim/release/libpairing_crypto_c.a" \
  "$TARGET_DIR/x86_64-apple-ios/release/libpairing_crypto_c.a" \
  -output "$SIM_FAT_DIR/libpairing_crypto_c.a"

echo "==> Creating XCFramework"
echo
xcodebuild -create-xcframework \
  -library "$TARGET_DIR/aarch64-apple-ios/release/libpairing_crypto_c.a" \
  -headers "$OBJC_HEADERS_DIR" \
  -library "$SIM_FAT_DIR/libpairing_crypto_c.a" \
  -headers "$OBJC_HEADERS_DIR" \
  -output "$XCFRAMEWORK_PATH"

echo "==> Copying Objective-C headers"
echo
rsync -a --include="*.h" --include="*.m" --exclude="*" "$OBJC_HEADERS_DIR"/ "$OBJC_DST_DIR"/

echo "✅ Built $XCFRAMEWORK_PATH"
