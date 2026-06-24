#!/bin/bash

# 定义版本号
VERSION="v1.1"

# 在脚本开始时输出版本信息
echo "RSA 密钥加密脚本 - 版本: $VERSION"
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

# 检查输入文件参数
if [ -z "$INPUT_FILE" ]; then
    echo "错误：请指定要加密的文件路径"
    echo "用法: $0 [--secret-path <路径>] <输入文件>"
    exit 1
fi

# 检查文件是否存在
if [ ! -f "$INPUT_FILE" ]; then
    echo "错误：文件 '$INPUT_FILE' 不存在"
    exit 1
fi

# 在原始文件名后直接添加 .enc 后缀
OUTPUT_FILE="${INPUT_FILE}.enc"

# 从统一API获取UUID和RSA密钥对 (POST请求)
echo "正在从 $KEY_AND_UUID_API_URL 获取 UUID 和密钥对..."
API_RESPONSE=$(curl -s -X POST "$KEY_AND_UUID_API_URL" \
  -H "Content-Type: application/json" \
  -d '{}') # 即使不需要请求体，也要发送一个空的JSON对象

# 检查API响应
if [ -z "$API_RESPONSE" ]; then
    echo "错误：无法从API获取密钥对或UUID，API响应为空。"
    exit 1
fi

# 检查API响应是否包含错误状态
if echo "$API_RESPONSE" | jq -e 'has("status") and .status == "error"' > /dev/null 2>&1; then
    ERROR_MESSAGE=$(echo "$API_RESPONSE" | jq -r '.message')
    echo "错误：API返回错误: $ERROR_MESSAGE"
    echo "完整API响应: $API_RESPONSE"
    exit 1
fi

# 提取公钥、私钥和UUID
PUBLIC_KEY_PEM=$(echo "$API_RESPONSE" | jq -r '.public_key_pem')
PRIVATE_KEY_PEM=$(echo "$API_RESPONSE" | jq -r '.private_key_pem')
UUID=$(echo "$API_RESPONSE" | jq -r '.uuid')

# 检查提取结果
if [ -z "$PUBLIC_KEY_PEM" ] || [ -z "$PRIVATE_KEY_PEM" ] || [ -z "$UUID" ]; then
    echo "错误：无法从API响应中提取公钥、私钥或UUID。"
    echo "API响应: $API_RESPONSE"
    exit 1
fi

# 保存密钥到文件
echo "$PUBLIC_KEY_PEM" > public.pem
echo "$PRIVATE_KEY_PEM" > private.pem

# 验证API返回的公钥和私钥是否匹配 (可选，但推荐)
echo "正在验证公钥和私钥匹配性..."
openssl rsa -in private.pem -pubout -out public_from_private.pem &>/dev/null
if [ $? -ne 0 ]; then
    echo "警告：无法从私钥生成公钥进行匹配验证，可能是密钥格式问题或OpenSSL版本差异。"
    echo "请手动检查 private.pem 和 public.pem 的有效性。"
else
    CLEAN_PUBLIC=$(awk 'NF { if($0 !~/^-/){print} }' public.pem)
    CLEAN_PUBLIC_FROM_PRIVATE=$(awk 'NF { if($0 !~/^-/){print} }' public_from_private.pem)

    if [ "$CLEAN_PUBLIC" != "$CLEAN_PUBLIC_FROM_PRIVATE" ]; then
        echo "错误：公钥和私钥不匹配！"
        echo "public.pem 内容："
        cat public.pem
        echo "public_from_private.pem 内容："
        cat public_from_private.pem
        rm -f private.pem public.pem public_from_private.pem # 清理密钥文件
        exit 1
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
ENCRYPTED_DATA_BASE64=$(openssl enc -aes-256-cbc -pbkdf2 -salt -in "$INPUT_FILE" -pass pass:"$AES_KEY" | base64 -w 0)

if [ $? -ne 0 ]; then
  echo "错误：文件AES加密失败"
  rm -f private.pem public.pem public_from_private.pem # 清理密钥文件
  exit 1
fi

# 3. 用RSA公钥加密AES密钥，并将结果Base64编码
ENCRYPTED_KEY_BASE64=$(echo -n "$AES_KEY" | openssl pkeyutl -encrypt -pubin -inkey public.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 | base64 -w 0)

if [ $? -ne 0 ]; then
  echo "错误：AES密钥RSA加密失败。请检查 public.pem 是否有效。"
  rm -f private.pem public.pem public_from_private.pem # 清理密钥文件
  exit 1
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
rm -f private.pem public.pem public_from_private.pem
unset AES_KEY
unset ENCRYPTED_KEY_BASE64
unset ENCRYPTED_DATA_BASE64

echo "加密完成！"
exit 0
