# e2txt-go

![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Status](https://img.shields.io/badge/status-stable-brightgreen)

易语言 `.e` / `.ec` 源码与文本互转的 Go 命令行工具：**反编译为易语言文本，也能反向写回 `.e`**。

全部结构与算法均经真实样本逐项验证，解析结果精确可靠。

## 安装

```bash
go build -o e2txt-go ./cmd/e2txt
```

## 用法

```bash
# 工程统计
./e2txt-go -mode info  -src 例子.e

# 结构化查看（支持库 / 程序集 / 子程序 / DLL / 窗口）
./e2txt-go -mode view  -src 例子.e

# 反编译为易语言文本源码
./e2txt-go -mode source -src 例子.e -dst 还原源码.e.txt

# 导出完整解析结构（JSON）
./e2txt-go -mode json  -src 例子.e

# 反向生成：把模型写回 .e（字节级无损）
./e2txt-go -mode build -src 例子.e -dst 重建.e

# 指定支持库文件，还原任意库（含第三方库）的命令名
./e2txt-go -mode source -src 例子.e -fne krnln.fne,eAPI.fne -dst 还原源码.e.txt

# 仅列出某个支持库里的全部命令表
./e2txt-go -fne eAPI.fne -fne-list
```

| 模式 | 说明 |
|------|------|
| `info` | 版本、段数及符号统计 |
| `view` | 列出全部可读符号 |
| `source` | 反编译字节码 → 易语言文本（控制流、运算符、真实库命令名） |
| `json` | 导出完整结构 |
| `build` | 结构化模型 → `.e`（校验通过后写出） |

| 参数 | 说明 |
|------|------|
| `-fne` | 支持库文件 `.fne`/`.fnr`，可重复或逗号分隔；用于还原任意库命令名 |
| `-fne-list` | 仅列出 `-fne` 指定库的命令表 |

## 能力

- **完整解析**：文件容器、段序列、段名 XOR 解码；支持库、程序集、子程序、局部变量/参数、结构、DLL、常量、窗口与控件。
- **字节码反编译**：字面量、常量、枚举、变量、成员/数组访问、调用、运算符，以及如果/判断/四种循环等控制流。
- **命令名还原**：内置常见库命令表；也可用 `-fne` 直接静态读取任意支持库（无需 Windows / 无需安装易语言），把 `命令#N` 还原成真实中文命令名。
- **反向生成**：写回器按原始校验和与段头编码重建文件，`build` 可得到字节级一致的 `.e`；字节码 assembler 支持把语句/表达式重新编码为方法体。

## 说明

- 加密源码（WTLE）需密码解密，暂不支持。
- 未指定 `.fne` 且不在内置表中的命令，退化为 `支持库名.命令#N` 占位，不影响其余内容。
- 本项目用于逆向学习与个人数据恢复，请遵守相关软件许可。

## 协议

[MIT](LICENSE)
