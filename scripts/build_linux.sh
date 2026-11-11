#!/bin/bash
# ============================================================
# Linux 构建脚本 - ransom_simulator（amd64 / arm64 / armv7）
# 用法: ./build_linux.sh [encryptor|decryptor|all]
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build/linux"
CMD_DIR="$PROJECT_ROOT/cmd"

TARGET="${1:-all}"

echo ""
echo "============================================================"
echo "  Ransom Simulator - Linux Build Script (amd64 / arm64 / armv7)"
echo "============================================================"
echo ""

build_encryptor() {
    echo "[1/2] Building encryptor for Linux (amd64)..."
    cd "$CMD_DIR/encryptor/linux"

    # amd64：动态链接 + 静态链接
    GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/ransom_simulator_linux" .
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/ransom_simulator_linux_static" .
    echo "[OK] ransom_simulator_linux / ransom_simulator_linux_static"

    echo "[2/2] Building encryptor for Linux (arm64 + armv7)..."
    # arm64：动态链接 + 静态链接
    GOOS=linux GOARCH=arm64 go build -o "$BUILD_DIR/ransom_simulator_linux_arm64" .
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o "$BUILD_DIR/ransom_simulator_linux_arm64_static" .
    # armv7（32 位 ARM）
    GOOS=linux GOARCH=arm GOARM=7 go build -o "$BUILD_DIR/ransom_simulator_linux_arm" .
    CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -o "$BUILD_DIR/ransom_simulator_linux_arm_static" .
    echo "[OK] ransom_simulator_linux_arm64 / _arm64_static / _arm / _arm_static"
}

build_decryptor() {
    echo "[*] Building decryptor for Linux (amd64 / arm64 / armv7)..."
    cd "$CMD_DIR/decryptor"
    GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/decryptor_linux" .
    GOOS=linux GOARCH=arm64 go build -o "$BUILD_DIR/decryptor_linux_arm64" .
    GOOS=linux GOARCH=arm GOARM=7 go build -o "$BUILD_DIR/decryptor_linux_arm" .
    echo "[OK] decryptor_linux / decryptor_linux_arm64 / decryptor_linux_arm"
}

case "$TARGET" in
    all)
        build_encryptor
        build_decryptor
        ;;
    encryptor)
        build_encryptor
        ;;
    decryptor)
        build_decryptor
        ;;
    *)
        echo "Usage: $0 [encryptor|decryptor|all]"
        exit 1
        ;;
esac

echo ""
echo "============================================================"
echo "  Build completed! Output directory: $BUILD_DIR"
echo "============================================================"
ls -lh "$BUILD_DIR"/* 2>/dev/null || echo "(no files)"
echo ""