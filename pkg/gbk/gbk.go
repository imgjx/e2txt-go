// Package gbk 封装易语言 .e 源码使用的 GBK 编码转换。
//
// 易语言源码文件（.e/.ec）内部所有可读文本均以 GBK 编码存储。
// 本包在 golang.org/x/text 的基础上提供 Decode/Encode 两个便捷函数，
// 并对非法字节做容错处理，避免单个坏字节导致整个字段解析失败。
package gbk

import (
	"bytes"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

var (
	decoder = simplifiedchinese.GBK.NewDecoder()
	encoder = simplifiedchinese.GBK.NewEncoder()
)

// Decode 将 GBK 字节序列转换为 UTF-8 字符串。
// 非法字节会被替换为 U+FFFD，不会返回错误。
func Decode(b []byte) string {
	out, _, err := transform.Bytes(decoder, b)
	if err != nil {
		// 容错：逐字节解码，丢弃无法转换的字节
		var buf bytes.Buffer
		for _, c := range b {
			o, _, e := transform.Bytes(decoder, []byte{c})
			if e == nil && utf8.Valid(o) {
				buf.Write(o)
			}
		}
		return buf.String()
	}
	return string(out)
}

// Encode 将 UTF-8 字符串转换为 GBK 字节序列。
func Encode(s string) ([]byte, error) {
	out, _, err := transform.Bytes(encoder, []byte(s))
	return out, err
}

// IsGBKText 粗略判断一段字节是否"看起来像"完整的 GBK 文本：
// 所有字节要么构成合法的 GBK 双字节序列，要么是可打印 ASCII。
func IsGBKText(b []byte) bool {
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c >= 0x81 && c <= 0xFE && i+1 < len(b) && b[i+1] >= 0x40 && b[i+1] <= 0xFE && b[i+1] != 0x7F:
			i += 2
		case c >= 0x20 && c <= 0x7E:
			i++
		default:
			return false
		}
	}
	return true
}
