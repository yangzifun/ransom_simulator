#!/bin/bash

# ---------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------

# 加密脚本的路径
ENCRYPT_SCRIPT="./encrypt_osx.sh"

# 要加密的目录
TARGET_DIRECTORY="."  # 默认为当前目录

# 要加密的文件扩展名 (用空格分隔)
FILE_EXTENSIONS="txt pdf doc docx"

# ---------------------------------------------------------------------
# 检查依赖和参数
# ---------------------------------------------------------------------

# 检查加密脚本是否存在且可执行
if [ ! -x "$ENCRYPT_SCRIPT" ]; then
  echo "错误: 加密脚本 '$ENCRYPT_SCRIPT' 不存在或不可执行。"
  exit 1
fi

# 检查是否提供了目录参数
if [ $# -gt 0 ]; then
  TARGET_DIRECTORY="$1"
fi

# 检查目标目录是否存在
if [ ! -d "$TARGET_DIRECTORY" ]; then
  echo "错误: 目标目录 '$TARGET_DIRECTORY' 不存在。"
  exit 1
fi

# ---------------------------------------------------------------------
# 主要逻辑：递归查找并加密文件
# ---------------------------------------------------------------------

# 构建 find 命令的名称匹配条件
# 例如：-name "*.txt" -o -name "*.pdf"
FIND_NAME_CONDITIONS=""
# 设置内部字段分隔符，以便for循环正确处理空格分隔的扩展名
# 使用 save_IFS 来确保我们恢复到用户可能设置的任何 IFS
save_IFS="$IFS"
IFS=" "
for ext in $FILE_EXTENSIONS; do
  if [ -z "$FIND_NAME_CONDITIONS" ]; then
    FIND_NAME_CONDITIONS="-name \"*.$ext\""
  else
    FIND_NAME_CONDITIONS="$FIND_NAME_CONDITIONS -o -name \"*.$ext\""
  fi
done
IFS="$save_IFS" # 恢复IFS到默认值或之前的值

# 构建完整的 find 命令字符串，并对括号进行转义
# 需要对 eval 传入的字符串中的 ( 和 ) 进行额外的转义，使它们被 eval 后仍然是字面量
FIND_COMMAND_STRING="find \"$TARGET_DIRECTORY\" -type f \\( $FIND_NAME_CONDITIONS \\) -print0"

# 调试输出构建的命令字符串
echo "调试: 执行的 find 命令字符串: $FIND_COMMAND_STRING"

# 执行 find 命令并管道到 while 循环
eval "$FIND_COMMAND_STRING" |
  while IFS= read -r -d $'\0' file; do
    echo "正在加密: $file"
    "$ENCRYPT_SCRIPT" "$file"
    if [ $? -ne 0 ]; then
      echo "  错误: 加密 '$file' 失败。"
    else
      echo "  成功加密: $file"
    fi
  done

echo "批量加密完成。"
exit 0
