#!/usr/bin/env bash

set -e

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  if [ -n "${ANDROID_SDK_ROOT:-}" ] && [ -d "$ANDROID_SDK_ROOT/ndk" ]; then
    latest_ndk="$(ls -1 "$ANDROID_SDK_ROOT/ndk" | sort -V | tail -1)"
    ANDROID_NDK_HOME="$ANDROID_SDK_ROOT/ndk/$latest_ndk"
  elif [ -n "${ANDROID_HOME:-}" ] && [ -d "$ANDROID_HOME/ndk" ]; then
    latest_ndk="$(ls -1 "$ANDROID_HOME/ndk" | sort -V | tail -1)"
    ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$latest_ndk"
  fi
fi

if [ -z "${ANDROID_NDK_HOME:-}" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
  echo "ERROR: ANDROID_NDK_HOME must point to an installed NDK (e.g. \$ANDROID_SDK_ROOT/ndk/26.x.y)"
  exit 1
fi

export ANDROID_NDK_HOME
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
export ANDROID_NDK="$ANDROID_NDK_HOME"

ROOT_DIRECTORY=$(cd "$(dirname "${BASH_SOURCE[0]}")" && cd ../../.. && pwd)

# set the directory for the c wrapper
JAVA_WRAPPER_DIRECTORY="$ROOT_DIRECTORY/wrappers/java"

# set the output directory
OUTPUT_DIRECTORY="$ROOT_DIRECTORY/wrappers/react-native/android/lib"

echo "----------------------------------------------"
echo
echo " JAVA_WRAPPER_DIRECTORY=$JAVA_WRAPPER_DIRECTORY"
echo "       OUTPUT_DIRECTORY=$OUTPUT_DIRECTORY"
echo
echo "----------------------------------------------"

if [ -d $OUTPUT_DIRECTORY ]; then
    rm -rf $OUTPUT_DIRECTORY/*
fi

mkdir -p $OUTPUT_DIRECTORY
mkdir -p $OUTPUT_DIRECTORY/native

# Build the Java wrapper for the IOS platform target
cd $JAVA_WRAPPER_DIRECTORY && ./gradlew clean buildAndCopyJniLibrariesAndroid jar

# Extract artifact version
PROJECT_PROPERTIES=$(./gradlew properties --no-daemon --console=plain -q)
VERSION=$(echo "$PROJECT_PROPERTIES" | grep '^version:' | awk '{printf $2}')
BUILD_DIRECTORY=$(echo "$PROJECT_PROPERTIES" | grep '^buildDir:' | awk '{printf $2}')
LIBRARY_FILE=$(echo "$PROJECT_PROPERTIES" | grep '^archivesBaseName:' | awk '{printf $2}')

# Copy class files to the external libraries folder
cp $JAVA_WRAPPER_DIRECTORY/build/libs/$LIBRARY_FILE-$VERSION.jar \
   $OUTPUT_DIRECTORY/$LIBRARY_FILE.jar

# Copy native libraries to the external libraries folder
cp -r $BUILD_DIRECTORY/native/android/* $OUTPUT_DIRECTORY/native
