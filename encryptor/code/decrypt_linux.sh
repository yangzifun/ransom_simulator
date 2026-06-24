#!/bin/bash

# 确保脚本在遇到错误时立即退出
set -e

# 定义版本号
VERSION="v1.0-Linux" # 增加了版本号以示修改，并与功能匹配，这是解密脚本

# 在脚本开始时输出版本信息
echo "RSA 密钥解密脚本 - 版本: $VERSION"
echo "-------------------------------------"

# 定义颜色常量
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查参数数量
if [ "$#" -ne 2 ]; then
    echo -e "${RED}用法: $0 <私钥文件> <加密文件>${NC}"
    echo "示例: $0 private_key.pem encrypted_file.enc"
    exit 1
fi

PRIVATE_KEY_FILE="$1"
ENCRYPTED_FILE="$2"

# 检查私钥文件是否存在
if [ ! -f "$PRIVATE_KEY_FILE" ]; then
    echo -e "${RED}错误: 私钥文件 '$PRIVATE_KEY_FILE' 不存在。${NC}"
    exit 1
fi

# 检查加密文件是否存在
if [ ! -f "$ENCRYPTED_FILE" ]; then
    echo -e "${RED}错误: 加密文件 '$ENCRYPTED_FILE' 不存在。${NC}"
    exit 1
fi

# 确定解密后的输出文件名
# 移除 .enc 后缀
DECRYPTED_OUTPUT_FILE="${ENCRYPTED_FILE%.enc}"

# 如果移除 .enc 后缀后文件名为空，或者没有 .enc 后缀，则可以设定一个默认规则
if [ "$DECRYPTED_OUTPUT_FILE" == "$ENCRYPTED_FILE" ]; then
    DECRYPTED_OUTPUT_FILE="${ENCRYPTED_FILE}.decrypted" # 如果没有 .enc，则添加 .decrypted 后缀
fi


echo -e "${YELLOW}正在分离加密文件内容和密钥...${NC}"

# 从加密文件中分离出RSA加密的AES密钥和加密数据
# 根据 encrypt_linux.sh 的输出格式进行调整
# 格式:
# ---BEGIN_AES_KEY---
# <Base64 编码的 RSA 加密的 AES 密钥>
# ---END_AES_KEY---
# ---BEGIN_ENCRYPTED_DATA---
# <Base64 编码的 AES 加密的数据>
# ---END_ENCRYPTED_DATA---
# ---END_ENCRYPTED_FILE_AND_KEY---

# 提取 RSA 加密的 AES 密钥部分
ENCRYPTED_AES_KEY_BASE64=$(awk '/---BEGIN_AES_KEY---/{flag=1;next}/---END_AES_KEY---/{flag=0} flag' "$ENCRYPTED_FILE" | tr -d '\n' | tr -d '\r')

# 提取 AES 加密的数据部分
ENCRYPTED_DATA_BASE64=$(awk '/---BEGIN_ENCRYPTED_DATA---/{flag=1;next}/---END_ENCRYPTED_DATA---/{flag=0} flag' "$ENCRYPTED_FILE" | tr -d '\n' | tr -d '\r')

if [ -z "$ENCRYPTED_AES_KEY_BASE64" ]; then
    echo -e "${RED}错误: 未能在 '$ENCRYPTED_FILE' 中找到 Base64 编码的 RSA 加密 AES 密钥部分（标记：---BEGIN_AES_KEY--- / ---END_AES_KEY---），或格式不正确。${NC}"
    exit 1
fi

if [ -z "$ENCRYPTED_DATA_BASE64" ]; then
    echo -e "${RED}错误: 未能在 '$ENCRYPTED_FILE' 中找到 Base64 编码的加密数据部分（标记：---BEGIN_ENCRYPTED_DATA--- / ---END_ENCRYPTED_DATA---），或格式不正确。${NC}"
    exit 1
fi

echo -e "${YELLOW}正在解密AES密钥...${NC}"

# 1. Base64 解码 RSA 加密的 AES 密钥密文
# 2. 使用私钥 RSA 解密，得到原始的 Base64 编码的 AES 密钥字符串
DECRYPTED_AES_KEY_STRING=$(echo -n "$ENCRYPTED_AES_KEY_BASE64" | base64 -d | openssl pkeyutl -decrypt -inkey "$PRIVATE_KEY_FILE" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256)

# 检查解密后的 AES 密钥字符串是否为空或解密失败
if [ -z "$DECRYPTED_AES_KEY_STRING" ]; then
    echo -e "${RED}错误: AES密钥解密失败或为空。${NC}"
    echo -e "${RED}请检查以下可能原因：${NC}"
    echo "1. 私钥 '$PRIVATE_KEY_FILE' 是否正确且与加密时使用的公钥匹配。"
    echo "2. 加密文件 '$ENCRYPTED_FILE' 中的RSA加密AES密钥部分是否完整和正确。"
    echo "3. RSA填充模式 (OAEP) 或哈希算法 (SHA256) 是否与加密时匹配。"
    exit 1
fi

# 检查解密后的 AES 密钥字符串是否是 Base64 编码的 32 字节原始密钥（44个Base64字符，结尾通常有=）
# 例如 openssl rand -base64 32 会生成 44 个字符
# 因为 encrypt_linux.sh 使用了 openssl rand -base64 32 来生成 AES_KEY
if ! echo "$DECRYPTED_AES_KEY_STRING" | base64 -d > /dev/null 2>&1 || [ $(echo -n "$DECRYPTED_AES_KEY_STRING" | base64 -d | wc -c) -ne 32 ]; then
    echo -e "${RED}错误: 解密出的AES密钥不是有效的Base64编码字符串或长度不为32字节。${NC}"
    echo -e "解密后的AES密钥字符串: ${RED}$DECRYPTED_AES_KEY_STRING${NC}"
    echo -e "请确认加密时AES密钥的生成方式和长度。"
    exit 1
fi


echo -e "${GREEN}AES密钥解密成功！${NC}"

echo -e "${YELLOW}正在解密数据...${NC}"

# 使用解密出的 AES 密钥字符串解密数据
# 注意：encrypt_linux.sh 使用了 -pass pass:"$AES_KEY"
# 所以解密时也需要使用 -pass pass:"$DECRYPTED_AES_KEY_STRING"
DECRYPTED_CONTENT=$(
    echo -n "$ENCRYPTED_DATA_BASE64" | base64 -d | \
    openssl enc -aes-256-cbc -d -pbkdf2 -pass pass:"$DECRYPTED_AES_KEY_STRING"
)

# 检查解密是否成功
if [ $? -ne 0 ]; then
    echo -e "${RED}错误: 数据解密失败。${NC}"
    echo -e "请检查以下可能原因："
    echo "1. 解密的AES密钥是否正确。"
    echo "2. 加密模式 (CBC) 和密钥派生函数 (PBKDF2) 是否与加密时匹配。"
    echo "3. 加密数据本身是否损坏。"
    exit 1
fi

if [ -z "$DECRYPTED_CONTENT" ]; then
    echo -e "${YELLOW}警告: 解密后的内容为空。如果这是预期行为，则忽略。${NC}"
fi

echo -e "${GREEN}数据解密成功！${NC}"

# 将解密后的内容输出到文件
echo -n "$DECRYPTED_CONTENT" > "$DECRYPTED_OUTPUT_FILE"

echo -e "${GREEN}解密后的内容已保存到 '$DECRYPTED_OUTPUT_FILE'${NC}"
echo ""

exit 0
