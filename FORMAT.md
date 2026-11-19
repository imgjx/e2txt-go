# 易语言 .e 文件格式规范（源码级精确版）

> 本文记录易语言 `.e` 二进制源码格式，并用真实样本 `例子.e` 逐项验证。
> 所有结构均由源码级分析确认，不是字节猜测。

## 1. 文件容器

### 1.1 文件头
```
int32 magic1   // 0x54574E43 = "CNWTEPRG"（未加密）；0x454C5457 = "WTLE"（加密）
int32 magic2   // 0x47525045 = "EPRG"（配合 magic1 组成 CNWTEPRG）
```
加密文件（设了源码密码）在第二字段给出加密类型（1=EStd / 0x00020001=EC），需密码解密。
本实现聚焦未加密源码。

### 1.2 段（Section）序列
文件是段的线性序列。每段头（小端）：
```
int32  0x15117319        // 段 Magic（这即早期笔记里的字节序列 19 73 11 15）
int32  InfoCheckSum
int32  Key               // 段唯一标识，如 0x03007319=程序段
byte[30] Name            // 段名，用 Key 的字节做 XOR 编码，NUL 结尾
int16  对齐填充
int32  Index
int32  IsOptional
int32  DataCheckSum
int32  DataLength
byte[40] 保留
byte[DataLength] Data
```
- **段名解码**（早期笔记误判为"按位取反类型签名"）：当 `Key != 0x07007319` 时，
  取 Key 的 4 个小端字节 `kb`，对每字节 `r[i] ^= kb[(i+1)%4]`，再按 GBK 解码至 NUL。
  样本解出的真实段名：`系统信息段`、`用户信息段`、`程序资源段`、`程序段`、`初始模块段` 等。
- 结束段 Key = `0x07007319`（EndOfFile）。

### 1.3 已知段 Key
| Key | 名称 | 内容 |
|-----|------|------|
| 0x01007319 | 用户信息段 | 工程名等配置 |
| 0x02007319 | 系统信息段 | 易语言/格式版本、语言码、文件类型 |
| 0x03007319 | 程序段 | 支持库、程序集、方法、变量、结构、DLL 命令 |
| 0x04007319 | 程序资源段 | 窗口、常量/图片/声音资源 |
| 0x05007319 | 可丢失程序段 | 可安全跳过的辅助数据 |
| 0x07007319 | 结束段 | 文件尾 |
| 0x08007319 | 初始模块段 | 启动代码 |
| 0x09007319 | 编辑信息段 | IDE 编辑器状态 |
| 0x0A007319 | 辅助信息段 | 事件索引 |
| 0x0B007319 | 程序集公开信息 | 公开属性 |
| 0x0C007319 | EC 依赖段 | 模块依赖 |
| 0x0D007319 | 易包信息段 | 包信息 |
| 0x0E007319 | 文件夹段 | 代码分组 |
| 0x10007319 | 配置扩展段 | |
| 0x11007319 | 条件编译段 | |

## 2. 基础读取原语（ExtensionMethod.cs）

| 方法 | 编码 |
|------|------|
| `ReadStringWithLengthPrefix` | `int32 字节数 + GBK 字节`（这就是早期笔记里的"4字节长度+GBK"，确认无误） |
| `ReadBStr` | `int32 长度(含终止符)`；0=null；否则 `长度-1` 字节 GBK + 1 字节 `\0` |
| `ReadCStyleString` | NUL 结尾 GBK |
| `ReadMfcStyleCountPrefix` | `uint16` 计数；`0xFFFF` 表示后跟 `int32` 计数 |
| `ReadBlocksWithIdAndMemoryAddress` | `int32 headerSize(=count*8)` + `int32[count] ids` + `int32[count] 地址` + 连续元素数据 |
| `ReadBlocksWithIdAndOffset` | `int32 count` + `int32 size` + `int32[count] ids` + `int32[count] offsets` + 按偏移寻址的元素 |

## 3. 程序段（CodeSection）

解析顺序（非加密 EC）：图标 → 调试参数 → **程序集 → 方法 → 全局变量 → 结构 → DLL 命令**。

各结构字段（均用上面的原语读取）：

- **程序集 ClassInfo**：`Form, BaseClass, Name, Comment, Methods(int32列表), 程序集变量`
- **方法 MethodInfo**：`Class, Flags, ReturnDataType, Name, Comment, 局部变量, 参数, 6 段 CodeData`
- **DLL 命令 DllDeclareInfo**：`Flags, ReturnDataType, Name, Comment, LibraryName, EntryPoint, 参数`
- **结构 StructInfo**：`Flags, Name, Comment, 成员`
- **变量 AbstractVariableInfo**：`DataType, Flags(int16), UBound(byte个数 + int32数组), Name, Comment`
- **支持库 LibraryRef**：MFC 字符串列表，每项用 `\r` 分割为 `文件名, GUID, 主版本, 次版本, 名称`

### ID 类型高位（EplSystemId）
`Type_Method=0x04000000`、`Type_FormClass=0x19000000`、`Type_Dll=0x0A000000`、
`Type_Local=0x25000000`、`Type_FormControl=0x16000000` 等。`GetType(id)=id & 0xFF000000`。
数据类型：`0x80000004`=文本型、`0x80000301`=整数型、`0x80000002`=逻辑型……（详见源码 EplSystemId.cs）。

## 4. 方法字节码反编译（核心中的核心）

方法的 `CodeData` 是 6 段长度前缀字节数组；只有第 6 段 `ExpressionData` 是字节码指令流，
前 5 段（行偏移、块偏移、方法/变量/常量引用表）是 IDE 辅助元数据。

### 4.1 语句类型字节（KnownTypeId）
| 字节 | 含义 | 字节 | 含义 |
|------|------|------|------|
| 0x6A | 常规调用 | 0x6B | 如果 (IfElse) |
| 0x6C | 如果真 (If) | 0x6D/0x6E | 判断开始/Case (Switch) |
| 0x70 | 循环开始 | 0x71 | 循环结束 |
| 0x50/0x51 | 否则/如果结束 | 0x52/0x53/0x54 | 各类块结束 |
| 0x6F | 默认 | 0x55 | 循环体结束 |

### 4.2 表达式类型字节
`0x17`=double、`0x3B`=int32 紧凑整数、`0x18`=逻辑型(int16)、`0x19`=日期(OADate)、
`0x1A`=文本(BStr)、`0x1B/0x1C`=常量、`0x23`=枚举常量、`0x38`=变量/ThisCall、
`0x39`=成员访问、`0x3A`=数组访问、`0x21`=调用、`0x01`=参数表结束、`0x20`=数组结束。

### 4.3 调用头（12 字节 + 参数区）
```
int32 methodId
int16 libraryId      // >=0 支持库索引; -1 空; -2 用户子程序; -3 DLL命令
int16 flag           // 0x20=屏蔽, 0x10=InvokeSpecial
BStr  unexaminedCode
BStr  comment
byte  0x36 或 0x38   // 0x36=普通参数表; 0x38=ThisCall(先 Target)
参数表: 多个表达式连续排列, 以 0x01 结束（无长度前缀）
```

### 4.4 运算符（LibraryId=0 且 MethodId 命中映射）
`*`=15, `/`=16, `\`=17, `%`=18, `+`=19, `-`=20, 一元负=21,
`==`=38 … `=`=52。反编译时转为中缀并按优先级加括号。

### 4.5 循环 MethodId 映射
`3`=判断循环(While)、`5`=循环判断(DoWhile)、`7`=计次循环、`9`=变量循环(For)。

### 4.6 立即数编码（重要更正）
早期笔记猜测的"按位取反"是错的。立即数用的是 **`+1/-1` 偏置**：
库常量、枚举成员、库类型 ID 写入时 `+1`，解析时 `-1`（为了让 0 表示"无效"）。

### 4.7 反编译算法
逐字节扫描找到 KnownTypeId → 解析调用头 → 按语句类型递归解析子块（靠结束标记回退指针）
→ 参数表/表达式以哨兵字节终止。详见 `pkg/epl/stmt.go`、`pkg/epl/expr.go`。

## 5. 命令名的来源与边界

`.e` 文件里**不硬编码支持库命令名/参数**，它们来自易语言安装目录下的 `.fne` 支持库文件。
因此完整的"命令名还原"必须依赖本地支持库环境。
本实现：
- 用户自定义符号（程序集/子程序/变量/常量/结构/DLL 命令/窗口控件）：**精确还原**（信息就在文件里）。
- 运算符、控制结构：**精确还原**。
- 支持库命令：因离线无 `.fne`，以 `支持库名.命令#N` 占位；接入 `.fne` 命令表即可补全。
- 加密源码（WTLE）：需密码，暂不支持。

## 6. 转换流程

```
.e 二进制
  ├─ 校验 CNWTEPRG 头
  ├─ 顺序读取各段（段名 XOR 解码）
  ├─ 系统信息段 → 确定编码
  ├─ 程序资源段 → 窗口 + 常量/资源
  ├─ 程序段 → 支持库/程序集/方法/变量/结构/DLL
  ├─ 每个方法: ExpressionData → 语句/表达式 AST
  └─ AST + 名称映射 → 易语言文本源码
```
