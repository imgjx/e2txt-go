package epl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"e2txt-go/pkg/gbk"
)

// 本文件负责把结构化模型写回 .e 二进制。
// 校验和算法、段名 XOR 编码、段头布局均按原始格式实现，
// 因此 Load(Save(x)) 可以做到字节级无损往返。

// Writer 是简易的小端字节缓冲区（对应 BinaryWriter + MemoryStream）。
type Writer struct {
	buf []byte
}

func NewWriter() *Writer { return &Writer{} }

func (w *Writer) WriteByte(b byte) { w.buf = append(w.buf, b) }
func (w *Writer) WriteBytes(b []byte) { w.buf = append(w.buf, b...) }
func (w *Writer) WriteZeros(n int) {
	for i := 0; i < n; i++ { w.buf = append(w.buf, 0) }
}
func (w *Writer) WriteInt16(v int16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], uint16(v))
	w.WriteBytes(b[:])
}
func (w *Writer) WriteUInt16(v uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	w.WriteBytes(b[:])
}
func (w *Writer) WriteInt32(v int32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	w.WriteBytes(b[:])
}
func (w *Writer) WriteUInt32(v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	w.WriteBytes(b[:])
}
func (w *Writer) WriteUInt64(v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	w.WriteBytes(b[:])
}
func float64bits(f float64) uint64 { return math.Float64bits(f) }
func gbkEncode(s string) ([]byte, error) { return gbk.Encode(s) }
func (w *Writer) WriteBytesWithLengthPrefix(b []byte) {
	w.WriteInt32(int32(len(b)))
	w.WriteBytes(b)
}
func (w *Writer) Bytes() []byte { return w.buf }

// checkSum 对应 ProjectFileWriter.GetCheckSum：按 4 字节分桶异或，小端组装。
func checkSum(data []byte) int32 {
	var c [4]byte
	for i, b := range data {
		c[i&0x3] ^= b
	}
	return int32(uint32(c[0]) | uint32(c[1])<<8 | uint32(c[2])<<16 | uint32(c[3])<<24)
}

// encodeName 对应 ProjectFileWriter.EncodeName：GBK 编码到 30 字节并按 key 异或。
func encodeName(key int32, name string) []byte {
	r := make([]byte, 30)
	if name != "" {
		b, err := gbk.Encode(name)
		if err == nil && len(b) > 30 {
			b = b[:30]
		}
		copy(r, b)
	}
	if key != 0x07007319 {
		kb := []byte{byte(key), byte(key >> 8), byte(key >> 16), byte(key >> 24)}
		for i := range r {
			r[i] ^= kb[(i+1)%4]
		}
	}
	return r
}

// Save 把 EFile 序列化为完整的 .e 文件字节流（无加密 CNWTEPRG 格式）。
// 逐段写回时保留解析阶段保存的原始数据，仅重算段头校验和与序号，
// 从而对未修改的工程实现字节级无损往返。
func Save(f *EFile) ([]byte, error) {
	if len(f.Sections) == 0 {
		return nil, errors.New("没有可写出的段")
	}
	w := NewWriter()
	w.WriteUInt32(0x54574E43) // CNWT
	w.WriteUInt32(0x47525045) // EPRG （合起来 0x4752504554574E43 = CNWTEPRG）
	for i, sec := range f.Sections {
		raw := sec.Extra
		if raw == nil {
			raw = &RawSection{Name: sec.Name, Key: sec.Key, Data: sec.Raw,
				IsOptional: sec.Extra == nil && sec.Key == SecLosable}
		}

		// 构造 headerData（对应 WriteSection 内部的 MemoryStream）
		hw := NewWriter()
		hw.WriteInt32(raw.Key)
		hw.WriteBytes(encodeName(raw.Key, raw.Name))
		hw.WriteZeros(2)
		hw.WriteInt32(int32(i + 1)) // index 从 1 开始
		if raw.IsOptional {
			hw.WriteInt32(1)
		} else {
			hw.WriteInt32(0)
		}
		hw.WriteInt32(checkSum(raw.Data))
		hw.WriteInt32(int32(len(raw.Data)))
		hw.WriteZeros(40)
		header := hw.Bytes()

		w.WriteUInt32(0x15117319) // 段 Magic
		w.WriteInt32(checkSum(header))
		w.WriteBytes(header)
		w.WriteBytes(raw.Data)
	}
	return w.Bytes(), nil
}

// VerifyRoundTrip 把 f 写回后再解析，逐段比对原始数据是否完全一致。
// 用于验证写回逻辑的正确性，返回 nil 表示无损。
func VerifyRoundTrip(f *EFile) error {
	out, err := Save(f)
	if err != nil {
		return err
	}
	g, err := Load(out)
	if err != nil {
		return fmt.Errorf("回读失败: %w", err)
	}
	if len(g.Sections) != len(f.Sections) {
		return fmt.Errorf("段数不一致: %d vs %d", len(g.Sections), len(f.Sections))
	}
	for i := range f.Sections {
		a, b := f.Sections[i].Raw, g.Sections[i].Raw
		if len(a) != len(b) {
			return fmt.Errorf("第 %d 段长度不一致: %d vs %d", i+1, len(a), len(b))
		}
		for j := range a {
			if a[j] != b[j] {
				return fmt.Errorf("第 %d 段第 %d 字节不一致: %02X vs %02X", i+1, j, a[j], b[j])
			}
		}
	}
	return nil
}
