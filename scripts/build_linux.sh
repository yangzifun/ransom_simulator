#!/bin/bash
# ============================================================
# Linux 构建脚本 - ransom_simulator
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
echo "  Ransom Simulator - Linux Build Script"
echo "============================================================"
echo ""

build_encryptor() {
    echo "[1/2] Building encryptor for Linux (amd64)..."
    cd "$CMD_DIR/encryptor/linux"
    
    # 动态链接版本
    GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/encryptor" .
    echo "[OK] encryptor built successfully."
    
    # 静态链接版本
    echo "[2/2] Building static encryptor for Linux (amd64)..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/encryptor_static" .
    echo "[OK] encryptor_static built successfully."
}

build_decryptor() {
    echo "[*] Building decryptor for Linux (amd64)..."
    cd "$CMD_DIR/decryptor"
    GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/decryptor" .
    echo "[OK] decryptor built successfully."
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