#!/bin/bash

# 定义版本号
VERSION="v1.0-macos"

# 在脚本开始时输出版本信息
echo "RSA 密钥解密脚本 (macOS) - 版本: $VERSION"
echo "-------------------------------------"

# 函数：错误处理和退出
function error_exit {
    local message="$1"
    echo "错误：$message" >&2 # 错误信息输出到 stderr
    exit 1
}

# 函数：清理敏感数据 (仅清除变量，不删除私钥文件，因为私钥可能需要保留)
function cleanup_sensitive_vars {
    unset AES_KEY ENCRYPTED_KEY_BASE64 ENCRYPTED_DATA_BASE64 DECRYPTED_AES_KEY
    echo "敏感变量已清理。"
}

# 检查输入文件参数
if [ $# -lt 2 ]; then # 现在需要至少两个参数：私钥和加密文件
    error_exit "请指定私钥文件路径和要解密的加密文件路径。\n用法: $0 <私钥文件路径> <输入文件.enc>"
fi

PRIVATE_KEY_FILE="$1" # 第一个参数现在是私钥文件
INPUT_FILE="$2"       # 第二个参数现在是加密文件

# 检查私钥文件是否存在
if [ ! -f "$PRIVATE_KEY_FILE" ]; then
    error_exit "私钥文件 '$PRIVATE_KEY_FILE' 不存在。请确保私钥文件存在或提供正确的路径。"
fi

# 检查输入文件是否存在
if [ ! -f "$INPUT_FILE" ]; then
    error_exit "加密文件 '$INPUT_FILE' 不存在"
fi

# 确定输出文件名
# 如果输入是 example.txt.enc，输出应为 example.txt
if [[ "$INPUT_FILE" == *.enc ]]; then
    OUTPUT_FILE="${INPUT_FILE%.enc}"
else
    # 如果文件没有 .enc 扩展名，我们无法安全地推断原始文件名
    # 建议用户手动指定或输出到临时文件
    echo "警告：输入文件 '$INPUT_FILE' 没有 '.enc' 扩展名。解密后将输出到 '${INPUT_FILE}.decrypted'"
    OUTPUT_FILE="${INPUT_FILE}.decrypted"
fi


echo "正在解析加密文件 '$INPUT_FILE'..."

# 提取 AES 密钥和加密数据
# 使用 awk 来精确提取标记之间的内容
ENCRYPTED_KEY_BASE64=$(awk '/---BEGIN_AES_KEY---/{flag=1;next}/---END_AES_KEY---/{flag=0}flag' "$INPUT_FILE")
ENCRYPTED_DATA_BASE64=$(awk '/---BEGIN_ENCRYPTED_DATA---/{flag=1;next}/---END_ENCRYPTED_DATA---/{flag=0}flag' "$INPUT_FILE")

# 检查提取结果
if [ -z "$ENCRYPTED_KEY_BASE64" ]; then
    error_exit "未能从文件 '$INPUT_FILE' 中提取加密的AES密钥。请检查文件格式。"
fi
if [ -z "$ENCRYPTED_DATA_BASE64" ]; then
    error_exit "未能从文件 '$INPUT_FILE' 中提取加密的数据。请检查文件格式。"
fi

echo "AES密钥和加密数据已成功提取。"

echo "正在使用私钥 '$PRIVATE_KEY_FILE' 解密AES密钥..."

# 1. 用RSA私钥解密AES密钥
# openssl base64 -d -A 用于从单行Base64解码
# openssl pkeyutl -decrypt 默认使用 PKCS#1 v1.5 padding。
# 需要明确指定 OAEP padding 和 SHA-256 哈希算法，以确保兼容加密脚本。
DECRYPTED_AES_KEY=$(echo -n "$ENCRYPTED_KEY_BASE64" | openssl base64 -d -A | openssl pkeyutl -decrypt -inkey "$PRIVATE_KEY_FILE" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 2>/dev/null)

if [ $? -ne 0 ]; then
  error_exit "AES密钥RSA解密失败。请检查私钥文件 '$PRIVATE_KEY_FILE' 是否有效且与加密时使用的公钥匹配，以及RSA填充模式是否正确。"
fi

if [ -z "$DECRYPTED_AES_KEY" ]; then
    error_exit "解密后的AES密钥为空。请检查私钥是否正确，或加密脚本的密钥生成方式。"
fi

echo "AES密钥解密成功。"

echo "正在使用解密后的AES密钥解密文件内容..."

# 2. 用解密后的AES密钥解密文件内容
# openssl base64 -d -A 用于从单行Base64解码
# -pbkdf2 和 -salt 确保加密强度，并在加密数据中包含盐值
echo -n "$ENCRYPTED_DATA_BASE64" | openssl base64 -d -A | openssl enc -d -aes-256-cbc -pbkdf2 -salt -pass pass:"$DECRYPTED_AES_KEY" > "$OUTPUT_FILE"

if [ $? -ne 0 ]; then
  error_exit "文件AES解密失败。可能原因：AES密钥不正确，或加密数据已损坏。"
fi

echo "文件已成功解密为 '$OUTPUT_FILE'"

# 清理敏感变量
cleanup_sensitive_vars

echo "解密完成！"
exit 0
