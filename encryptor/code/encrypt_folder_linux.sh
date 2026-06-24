#!/bin/bash

# 定义版本号
# [MODIFIED] 版本号递增，以反映功能变更
VERSION="v1.0"

# 在脚本开始时输出版本信息
echo "RSA 密钥文件夹加密脚本 (Linux) - 版本: $VERSION"
echo "-------------------------------------"

# 定义变量
# 统一的 UUID 和密钥获取接口
KEY_AND_UUID_API_URL="https://rsa-uuid.api.yangzifun.org" 
# [REMOVED] 移除了不再需要的 UPLOAD_UUID_API_URL 变量

# 定义临时文件名称
PUBLIC_KEY_FILE="public.pem"
PRIVATE_KEY_FILE="private.pem"
PUBLIC_FROM_PRIVATE_FILE="public_from_private.pem" # 用于密钥验证的临时文件

# 定义一个文件来记录所有加密文件和其UUID的映射
README_FILE="encrypted_files_summary.txt"

# 函数：错误处理和退出 (用于脚本的致命错误)
function error_exit {
    local message="$1"
    echo "错误：$message" >&2 # 输出到标准错误
    cleanup_temp_files # 调用清理临时文件
    exit 1
}

# 函数：清理临时密钥文件
function cleanup_temp_files {
    rm -f "$PUBLIC_KEY_FILE" "$PRIVATE_KEY_FILE" "$PUBLIC_FROM_PRIVATE_FILE" 2>/dev/null
}

# 检查是否安装了 jq
if ! command -v jq &> /dev/null; then
    echo "错误：未找到 'jq' 命令。'jq' 是必须的，请安装它 (例如: sudo apt-get install jq 或 sudo yum install jq)。" >&2
    exit 1
fi

# --- 核心加密函数 ---
function encrypt_single_file {
    local INPUT_FILE="$1"
    local OUTPUT_FILE="${INPUT_FILE}.enc"

    echo "----------------------------------------------------"
    echo "正在处理文件: '$INPUT_FILE'"

    # 检查文件是否存在
    if [ ! -f "$INPUT_FILE" ]; then
        echo "警告：文件 '$INPUT_FILE' 不存在，跳过。"
        return 1
    fi

    # 检查文件是否已经是加密文件
    if [[ "$INPUT_FILE" == *.enc ]]; then
        echo "警告：文件 '$INPUT_FILE' 似乎已经是加密文件，跳过。"
        return 1
    fi
    
    cleanup_temp_files

    # 从统一API获取UUID和RSA密钥对
    echo "正在从 $KEY_AND_UUID_API_URL 获取 UUID 和密钥对..."
    local API_RESPONSE
    API_RESPONSE=$(curl -s -X POST "$KEY_AND_UUID_API_URL" \
      -H "Content-Type: application/json" \
      -d '{}') 

    if [ -z "$API_RESPONSE" ]; then
        echo "错误：无法从API获取密钥对或UUID，API响应为空。跳过文件 '$INPUT_FILE'。" >&2
        return 1
    fi

    if echo "$API_RESPONSE" | jq -e 'has("status") and .status == "error"' &> /dev/null; then
        local ERROR_MESSAGE=$(echo "$API_RESPONSE" | jq -r '.message')
        echo "错误：API返回错误: $ERROR_MESSAGE。跳过文件 '$INPUT_FILE'。" >&2
        return 1
    fi

    local PUBLIC_KEY_PEM
    local PRIVATE_KEY_PEM
    local UUID

    PUBLIC_KEY_PEM=$(echo "$API_RESPONSE" | jq -r '.public_key_pem')
    PRIVATE_KEY_PEM=$(echo "$API_RESPONSE" | jq -r '.private_key_pem')
    UUID=$(echo "$API_RESPONSE" | jq -r '.uuid')

    if [ -z "$PUBLIC_KEY_PEM" ] || [ -z "$PRIVATE_KEY_PEM" ] || [ -z "$UUID" ]; then
        echo "错误：无法从API响应中提取公钥、私钥或UUID。跳过文件 '$INPUT_FILE'。" >&2
        return 1
    fi

    echo "$PUBLIC_KEY_PEM" > "$PUBLIC_KEY_FILE"
    echo "$PRIVATE_KEY_PEM" > "$PRIVATE_KEY_FILE"
    echo "RSA密钥对已成功获取。"

    # 验证公钥和私钥匹配性
    echo "正在验证公钥和私钥匹配性..."
    openssl rsa -in "$PRIVATE_KEY_FILE" -pubout -out "$PUBLIC_FROM_PRIVATE_FILE" &>/dev/null
    if [ $? -ne 0 ]; then
        echo "警告：无法从私钥生成公钥进行匹配验证。跳过文件 '$INPUT_FILE'。" >&2
        cleanup_temp_files
        return 1
    else
        local CLEAN_PUBLIC=$(awk 'NF { if($0 !~/^-/){print} }' "$PUBLIC_KEY_FILE")
        local CLEAN_PUBLIC_FROM_PRIVATE=$(awk 'NF { if($0 !~/^-/){print} }' "$PUBLIC_FROM_PRIVATE_FILE")

        if [ "$CLEAN_PUBLIC" != "$CLEAN_PUBLIC_FROM_PRIVATE" ]; then
            echo "错误：公钥和私钥不匹配！跳过文件 '$INPUT_FILE'。" >&2
            cleanup_temp_files
            return 1
        else
            echo "公钥和私钥匹配验证通过。"
        fi
    fi

    # [REMOVED] 移除了整个上传 UUID 的功能块。
    # 该功能已由统一的密钥API处理，不再需要单独的步骤。

    echo "正在加密文件 '$INPUT_FILE'..."
    local AES_KEY
    local ENCRYPTED_DATA_BASE64
    local ENCRYPTED_KEY_BASE64

    AES_KEY=$(openssl rand -base64 32) 
    ENCRYPTED_DATA_BASE64=$(openssl enc -aes-256-cbc -pbkdf2 -salt -in "$INPUT_FILE" -pass pass:"$AES_KEY" | base64 -w 0)

    if [ $? -ne 0 ]; then
      echo "错误：文件AES加密失败。跳过文件 '$INPUT_FILE'。" >&2
      return 1
    fi

    ENCRYPTED_KEY_BASE64=$(echo -n "$AES_KEY" | openssl pkeyutl -encrypt -pubin -inkey "$PUBLIC_KEY_FILE" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 | base64 -w 0)

    if [ $? -ne 0 ]; then
      echo "错误：AES密钥RSA加密失败。跳过文件 '$INPUT_FILE'。" >&2
      return 1
    fi

    echo "---BEGIN_AES_KEY---" > "$OUTPUT_FILE"
    echo "$ENCRYPTED_KEY_BASE64" >> "$OUTPUT_FILE"
    echo "---END_AES_KEY---" >> "$OUTPUT_FILE"
    echo "---BEGIN_ENCRYPTED_DATA---" >> "$OUTPUT_FILE"
    echo "$ENCRYPTED_DATA_BASE64" >> "$OUTPUT_FILE"
    echo "---END_ENCRYPTED_DATA---" >> "$OUTPUT_FILE"
    echo "---END_ENCRYPTED_FILE_AND_KEY---" >> "$OUTPUT_FILE"

    echo "文件已成功加密为 '$OUTPUT_FILE'"
    echo "关联的UUID: $UUID"

    echo "加密文件：$OUTPUT_FILE -> UUID: $UUID" >> "$README_FILE"
    cleanup_temp_files
    echo "文件 '$INPUT_FILE' 加密完成！"
    return 0
}

# --- 主脚本逻辑 ---
if [ $# -eq 0 ]; then
    error_exit "请指定要加密的文件夹路径。用法: $0 <文件夹路径>"
fi

TARGET_DIR="$1"

if [ ! -d "$TARGET_DIR" ]; then
    error_exit "指定的路径 '$TARGET_DIR' 不是一个有效的目录。"
fi

echo "开始加密文件夹 '$TARGET_DIR' 中的所有 .txt 文件..."
echo "加密结果和UUID将记录在 '$README_FILE' 中。"
echo "----------------------------------------------------" >> "$README_FILE"
echo "加密任务开始于: $(date)" >> "$README_FILE"
echo "版本: $VERSION" >> "$README_FILE"
echo "----------------------------------------------------" >> "$README_FILE"

find "$TARGET_DIR" -type f -name "*.txt" -print0 | while IFS= read -r -d $'\0' file; do
    encrypt_single_file "$file"
done

echo "----------------------------------------------------"
echo "所有 .txt 文件处理完毕。"
echo "加密结果摘要已保存到 '$README_FILE'。"
echo "加密任务完成于: $(date)" >> "$README_FILE"
echo "----------------------------------------------------" >> "$README_FILE"

exit 0
