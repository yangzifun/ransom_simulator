#!/bin/bash

# 定义版本号
VERSION="v3.2"

# 在脚本开始时输出版本信息
echo "RSA 密钥加密脚本 (macOS) - 版本: $VERSION"
echo "-------------------------------------"

# 定义变量
# 统一的 UUID 和密钥获取接口
BASE_API_URL="https://rsa-uuid.api.yangzifun.org"

# 默认安全路径（可自行修改）
# 当 --secret-path 参数未提供时使用此默认值
DEFAULT_SECRET_PATH="E56dSY"

# 默认 API URL（使用默认安全路径）
KEY_AND_UUID_API_URL="${BASE_API_URL}/${DEFAULT_SECRET_PATH}"

# 解析参数
SECRET_PATH=""
INPUT_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --secret-path)
      SECRET_PATH="$2"
      shift 2
      ;;
    *)
      INPUT_FILE="$1"
      shift
      ;;
  esac
done

# 如果提供了安全路径，覆盖默认值拼接到 API URL
if [ -n "$SECRET_PATH" ]; then
  KEY_AND_UUID_API_URL="${BASE_API_URL}/${SECRET_PATH}"
fi
echo "安全路径已配置，将通过 $KEY_AND_UUID_API_URL 访问 API"

# 定义临时文件名称
PUBLIC_KEY_FILE="public.pem"
PRIVATE_KEY_FILE="private.pem"
PUBLIC_FROM_PRIVATE_FILE="public_from_private.pem" # 用于密钥验证的临时文件

# 函数：错误处理和退出
function error_exit {
    local message="$1"
    echo "错误：$message" >&2 # 错误信息输出到 stderr
    cleanup
    exit 1
}

# 函数：清理临时文件
function cleanup {
    rm -f "$PUBLIC_KEY_FILE" "$PRIVATE_KEY_FILE" "$PUBLIC_FROM_PRIVATE_FILE" 2>/dev/null
    unset AES_KEY ENCRYPTED_KEY_BASE64 PUBLIC_KEY_PEM PRIVATE_KEY_PEM UUID
    echo "临时文件已清理。"
}

# 检查输入文件参数
if [ -z "$INPUT_FILE" ]; then
    error_exit "请指定要加密的文件路径。用法: $0 [--secret-path <路径>] <输入文件>"
fi

# 检查文件是否存在
if [ ! -f "$INPUT_FILE" ]; then
    error_exit "文件 '$INPUT_FILE' 不存在"
fi

# 在原始文件名后直接添加 .enc 后缀
OUTPUT_FILE="${INPUT_FILE}.enc"

# 检查是否安装了 jq
if ! command -v jq &> /dev/null; then
    echo "警告：未找到 'jq' 命令。脚本将尝试使用 'sed' 进行JSON解析，但这可能不如 'jq' 健壮。" >&2
fi

# 从统一API获取UUID和RSA密钥对 (POST请求)
echo "正在从 $KEY_AND_UUID_API_URL 获取 UUID 和密钥对..."
API_RESPONSE=$(curl -s -X POST "$KEY_AND_UUID_API_URL" \
  -H "Content-Type: application/json" \
  -d '{}') # 即使不需要请求体，也要发送一个空的JSON对象

# 检查API响应
if [ -z "$API_RESPONSE" ]; then
    error_exit "无法从API获取密钥对或UUID，API响应为空。"
fi

# 检查API响应是否包含错误状态
if echo "$API_RESPONSE" | jq -e 'has("status") and .status == "error"' > /dev/null 2>&1; then
    ERROR_MESSAGE=$(echo "$API_RESPONSE" | jq -r '.message')
    error_exit "API返回错误: $ERROR_MESSAGE (完整API响应: $API_RESPONSE)"
fi

# 提取公钥、私钥和UUID (优先使用 jq，否则使用 sed)
if command -v jq &> /dev/null; then
    PUBLIC_KEY_PEM=$(echo "$API_RESPONSE" | jq -r '.public_key_pem')
    PRIVATE_KEY_PEM=$(echo "$API_RESPONSE" | jq -r '.private_key_pem')
    UUID=$(echo "$API_RESPONSE" | jq -r '.uuid')
else
    PUBLIC_KEY_PEM=$(echo "$API_RESPONSE" | sed -n 's/.*"public_key_pem":"\([^"]*\)".*/\1/p' | sed 's/\\n/\n/g')
    PRIVATE_KEY_PEM=$(echo "$API_RESPONSE" | sed -n 's/.*"private_key_pem":"\([^"]*\)".*/\1/p' | sed 's/\\n/\n/g')
    UUID=$(echo "$API_RESPONSE" | sed -n 's/.*"uuid":"\([^"]*\)".*/\1/p')
fi


# 检查提取结果
if [ -z "$PUBLIC_KEY_PEM" ] || [ -z "$PRIVATE_KEY_PEM" ] || [ -z "$UUID" ]; then
    error_exit "无法从API响应中提取公钥、私钥或UUID。API响应: $API_RESPONSE"
fi

# 保存密钥到文件
printf "%s" "$PUBLIC_KEY_PEM" > "$PUBLIC_KEY_FILE"
printf "%s" "$PRIVATE_KEY_PEM" > "$PRIVATE_KEY_FILE"
echo "RSA密钥对已成功获取并保存为 $PUBLIC_KEY_FILE 和 $PRIVATE_KEY_FILE。"


# 验证API返回的公钥和私钥是否匹配
echo "正在验证公钥和私钥匹配性..."
openssl rsa -in "$PRIVATE_KEY_FILE" -pubout -out "$PUBLIC_FROM_PRIVATE_FILE" &>/dev/null
if [ $? -ne 0 ]; then
    echo "警告：无法从私钥生成公钥进行匹配验证，可能是密钥格式问题或OpenSSL版本差异。" >&2
    echo "请手动检查 private.pem 和 public.pem 的有效性。" >&2
else
    CLEAN_PUBLIC=$(awk 'NF { if($0 !~/^-/){print} }' "$PUBLIC_KEY_FILE")
    CLEAN_PUBLIC_FROM_PRIVATE=$(awk 'NF { if($0 !~/^-/){print} }' "$PUBLIC_FROM_PRIVATE_FILE")

    if [ "$CLEAN_PUBLIC" != "$CLEAN_PUBLIC_FROM_PRIVATE" ]; then
        error_exit "公钥和私钥不匹配！请检查API返回的密钥对。"
    else
        echo "公钥和私钥匹配验证通过。"
    fi
fi

# [REMOVED] 移除了整个上传 UUID 的功能块
# 该功能已由统一的密钥API处理，不再需要单独的步骤。

echo "正在加密文件 '$INPUT_FILE'..."
# ---------------------------------------------------------------------
# 加密逻辑：确保输出格式与解密脚本兼容
# ---------------------------------------------------------------------

# 1. 生成随机AES密钥 (Base64编码)
AES_KEY=$(openssl rand -base64 32)

# 2. 用AES加密文件内容，并将结果Base64编码
ENCRYPTED_DATA_BASE64=$(openssl enc -aes-256-cbc -pbkdf2 -salt -in "$INPUT_FILE" -pass pass:"$AES_KEY" | openssl base64 -e -A)

if [ $? -ne 0 ]; then
  error_exit "文件AES加密失败"
fi

# 3. 用RSA公钥加密AES密钥，并将结果Base64编码
ENCRYPTED_KEY_BASE64=$(echo -n "$AES_KEY" | openssl pkeyutl -encrypt -pubin -inkey "$PUBLIC_KEY_FILE" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 | openssl base64 -e -A)

if [ $? -ne 0 ]; then
  error_exit "AES密钥RSA加密失败。请检查 $PUBLIC_KEY_FILE 是否有效。"
fi

# 4. 将所有部分按照特定格式写入输出文件
echo "---BEGIN_AES_KEY---" > "$OUTPUT_FILE"
echo "$ENCRYPTED_KEY_BASE64" >> "$OUTPUT_FILE"
echo "---END_AES_KEY---" >> "$OUTPUT_FILE"
echo "---BEGIN_ENCRYPTED_DATA---" >> "$OUTPUT_FILE"
echo "$ENCRYPTED_DATA_BASE64" >> "$OUTPUT_FILE"
echo "---END_ENCRYPTED_DATA---" >> "$OUTPUT_FILE"
echo "---END_ENCRYPTED_FILE_AND_KEY---" >> "$OUTPUT_FILE"

# ---------------------------------------------------------------------

echo "文件已成功加密为 '$OUTPUT_FILE'"
echo "关联的UUID: $UUID"

# 记录UUID信息到readme.txt
echo "加密的文件名称：$OUTPUT_FILE : $UUID" >> readme.txt

# 清理临时文件和密钥
cleanup

echo "加密完成！"
exit 0
