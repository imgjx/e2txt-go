// Package epl 实现 .e 文件格式的精确读写与结构化解析。
// 本文件对应 C# 的 Internal/ExtensionMethod.cs —— 所有二进制读取原语。
package epl

import (
	"encoding/binary"
	"errors"
	"math"
)

// Reader 是一个基于字节切片的小端二进制读取器，等价于 C# BinaryReader + MemoryStream。
// 我们不使用 io.Reader，因为块解析需要频繁随机定位（BaseStream.Position = ...）。
type Reader struct {
	Data []byte
	Pos  int
}

func NewReader(data []byte) *Reader { return &Reader{Data: data, Pos: 0} }

func (r *Reader) Remaining() int { return len(r.Data) - r.Pos }

// ---------- 基础类型（全部小端） ----------

func (r *Reader) ReadByte() byte {
	if r.Pos >= len(r.Data) {
		return 0
	}
	b := r.Data[r.Pos]
	r.Pos++
	return b
}

func (r *Reader) ReadInt16() int16 {
	if r.Pos+2 > len(r.Data) {
		r.Pos = len(r.Data)
		return 0
	}
	v := int16(binary.LittleEndian.Uint16(r.Data[r.Pos:]))
	r.Pos += 2
	return v
}

func (r *Reader) ReadUInt16() uint16 {
	if r.Pos+2 > len(r.Data) {
		r.Pos = len(r.Data)
		return 0
	}
	v := binary.LittleEndian.Uint16(r.Data[r.Pos:])
	r.Pos += 2
	return v
}

func (r *Reader) ReadInt32() int32 {
	if r.Pos+4 > len(r.Data) {
		r.Pos = len(r.Data)
		return 0
	}
	v := int32(binary.LittleEndian.Uint32(r.Data[r.Pos:]))
	r.Pos += 4
	return v
}

func (r *Reader) ReadUInt32() uint32 {
	if r.Pos+4 > len(r.Data) {
		r.Pos = len(r.Data)
		return 0
	}
	v := binary.LittleEndian.Uint32(r.Data[r.Pos:])
	r.Pos += 4
	return v
}

func (r *Reader) ReadDouble() float64 {
	if r.Pos+8 > len(r.Data) {
		r.Pos = len(r.Data)
		return 0
	}
	v := math.Float64frombits(binary.LittleEndian.Uint64(r.Data[r.Pos:]))
	r.Pos += 8
	return v
}

func (r *Reader) ReadBytes(n int) []byte {
	if n < 0 {
		n = 0
	}
	if r.Pos+n > len(r.Data) {
		n = len(r.Data) - r.Pos
	}
	b := make([]byte, n)
	copy(b, r.Data[r.Pos:r.Pos+n])
	r.Pos += n
	return b
}

func (r *Reader) Seek(pos int) error {
	if pos < 0 || pos > len(r.Data) {
		return errors.New("seek out of range")
	}
	r.Pos = pos
	return nil
}

// ---------- ExtensionMethod 对应方法 ----------

// ReadBytesWithLengthPrefix: ReadBytes(ReadInt32())
func (r *Reader) ReadBytesWithLengthPrefix() []byte {
	return r.ReadBytes(int(r.ReadInt32()))
}

// ReadStringWithFixedLength: 读取定长文本，遇到第一个 0 截断。
func (r *Reader) ReadStringWithFixedLength(dec Decoder, length int) string {
	b := r.ReadBytes(length)
	if idx := indexByte(b, 0); idx != -1 {
		b = b[:idx]
	}
	return dec(b)
}

// ReadBStr: int32 长度（含终止符）；0 表示 null；读取 length-1 字节再跳过 1 字节终止符。
func (r *Reader) ReadBStr(dec Decoder) string {
	length := r.ReadInt32()
	if length == 0 {
		return ""
	}
	str := dec(r.ReadBytes(int(length) - 1))
	r.ReadByte()
	return str
}

// ReadStringWithLengthPrefix: ReadStringWithFixedLength(ReadInt32())
func (r *Reader) ReadStringWithLengthPrefix(dec Decoder) string {
	return r.ReadStringWithFixedLength(dec, int(r.ReadInt32()))
}

// ReadCStyleString: 读取以 0 结尾的字符串。
func (r *Reader) ReadCStyleString(dec Decoder) string {
	start := r.Pos
	for r.Pos < len(r.Data) && r.Data[r.Pos] != 0 {
		r.Pos++
	}
	b := r.Data[start:r.Pos]
	if r.Pos < len(r.Data) {
		r.Pos++ // 跳过 0
	}
	return dec(b)
}

// ReadMfcStyleCountPrefix: uint16 计数，0xFFFF 表示后面跟 int32 计数。
func (r *Reader) ReadMfcStyleCountPrefix() int {
	c := r.ReadUInt16()
	if c != 0xFFFF {
		return int(c)
	}
	return int(r.ReadInt32())
}

// ReadStringsAsListWithMfcStyleCountPrefix
func (r *Reader) ReadStringsAsList(dec Decoder) []string {
	count := r.ReadMfcStyleCountPrefix()
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, r.ReadStringWithLengthPrefix(dec))
	}
	return out
}

// ReadInt32sFixed: 读取 count 个 int32。
func (r *Reader) ReadInt32sFixed(count int) []int32 {
	if count < 0 {
		count = 0
	}
	out := make([]int32, count)
	for i := 0; i < count; i++ {
		out[i] = r.ReadInt32()
	}
	return out
}

// ReadInt32sWithByteSizePrefix: int32 字节数 / 4 得到个数。
func (r *Reader) ReadInt32sWithByteSizePrefix() []int32 {
	return r.ReadInt32sFixed(int(r.ReadInt32()) / 4)
}

// ReadInt16sWithByteSizePrefix: int32 字节数 / 2 得到个数。
func (r *Reader) ReadInt16sWithByteSizePrefix() []int16 {
	count := int(r.ReadInt32()) / 2
	out := make([]int16, count)
	for i := 0; i < count; i++ {
		out[i] = r.ReadInt16()
	}
	return out
}

// BlockElem 是一个带 id/offset 的子块解析结果，由 ReadBlocks* 系列返回。
// 这里用泛型函数指针由调用方定义具体解析。

// ReadBlocksWithIDAndOffset 对应 ReadBlocksWithIdAndOffest(count版):
//   int32 count; int32 size; int32[count] ids; int32[count] offsets;
//   for each: seek(start+offset[i]); int32 length; readFunc(elemReader, id)
// 返回解析后的 []interface{} 供调用方断言。
func (r *Reader) ReadBlocksWithIDAndOffset(readFunc func(er *Reader, id int32)) {
	count := int(r.ReadInt32())
	size := int(r.ReadInt32())
	_ = size
	endPos := r.Pos + size
	ids := r.ReadInt32sFixed(count)
	offsets := r.ReadInt32sFixed(count)
	start := r.Pos
	for i := 0; i < count; i++ {
		_ = r.Seek(start + int(offsets[i]))
		length := int(r.ReadInt32()) // 元素长度（解析函数通常会消费掉内容）
		_ = length
		readFunc(r, ids[i])
	}
	_ = r.Seek(endPos)
}

// ReadBlocksWithIDAndMemoryAddress 对应 ReadBlocksWithIdAndMemoryAddress:
//   int32 headerSize; count = headerSize/8; int32[count] ids; int32[count] addresses;
//   for each: readFunc(reader, id, address) —— 数据连续存放，无需 seek。
func (r *Reader) ReadBlocksWithIDAndMemAddr(readFunc func(er *Reader, id, memAddr int32)) {
	headerSize := int(r.ReadInt32())
	count := headerSize / 8
	ids := r.ReadInt32sFixed(count)
	addrs := r.ReadInt32sFixed(count)
	for i := 0; i < count; i++ {
		readFunc(r, ids[i], addrs[i])
	}
}

// Decoder 是一个字节→字符串的解码函数（通常是 gbk.Decode）。
type Decoder func([]byte) string

func indexByte(b []byte, v byte) int {
	for i, x := range b {
		if x == v {
			return i
		}
	}
	return -1
}
