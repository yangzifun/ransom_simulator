#!/bin/bash
# ============================================================
# macOS 构建脚本 - ransom_simulator
# 用法: ./build_macos.sh [encryptor|decryptor|all]
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build/macos"
CMD_DIR="$PROJECT_ROOT/cmd"

TARGET="${1:-all}"

echo ""
echo "============================================================"
echo "  Ransom Simulator - macOS Build Script"
echo "============================================================"
echo ""

build_encryptor() {
    echo "[1/2] Building encryptor for macOS (amd64)..."
    cd "$CMD_DIR/encryptor/linux"  # macOS 使用 linux 源码
    
    GOOS=darwin GOARCH=amd64 go build -o "$BUILD_DIR/encryptor_amd64" .
    echo "[OK] encryptor_amd64 built successfully."
    
    echo "[2/2] Building encryptor for macOS (arm64)..."
    GOOS=darwin GOARCH=arm64 go build -o "$BUILD_DIR/encryptor_arm64" .
    echo "[OK] encryptor_arm64 built successfully."
}

build_decryptor() {
    echo "[*] Building decryptor for macOS (amd64)..."
    cd "$CMD_DIR/decryptor"
    GOOS=darwin GOARCH=amd64 go build -o "$BUILD_DIR/decryptor_amd64" .
    echo "[OK] decryptor_amd64 built successfully."
    
    echo "[*] Building decryptor for macOS (arm64)..."
    GOOS=darwin GOARCH=arm64 go build -o "$BUILD_DIR/decryptor_arm64" .
    echo "[OK] decryptor_arm64 built successfully."
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