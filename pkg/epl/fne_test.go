package epl

import (
	"encoding/binary"
	"testing"

	"e2txt-go/pkg/gbk"
)

// buildFakeFne 构造一个最小 32 位 PE，模拟含 2 条命令的 .fne。
// 用于在无真实 .fne 文件时验证 magic 定位 / 结构偏移 / RVA 转换逻辑。
func buildFakeFne() []byte {
	imageBase := uint32(0x10000000)
	// 布局：DOS头(0x40) + PE头(0xF8) + 节表(0x28) -> .rdata @ file 0x200, RVA 0x2000
	dataFileOff := uint32(0x200)
	rdataVA := uint32(0x2000)
	buf := make([]byte, 0x1000)

	// DOS 头
	buf[0] = 'M'; buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:], 0x80) // e_lfanew
	pe := 0x80
	copy(buf[pe:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(buf[pe+4:], 0x14c) // Machine: i386
	binary.LittleEndian.PutUint16(buf[pe+6:], 1)    // NumberOfSections
	binary.LittleEndian.PutUint16(buf[pe+20:], 224) // SizeOfOptionalHeader
	opt := pe + 24
	binary.LittleEndian.PutUint16(buf[opt:], 0x10b) // PE32
	binary.LittleEndian.PutUint32(buf[opt+28:], imageBase)
	// 节表
	sec := opt + 224
	copy(buf[sec:], ".rdata\x00\x00")
	binary.LittleEndian.PutUint32(buf[sec+8:], 0x1000)  // VirtualSize
	binary.LittleEndian.PutUint32(buf[sec+12:], rdataVA) // VirtualAddress
	binary.LittleEndian.PutUint32(buf[sec+16:], 0x1000)  // SizeOfRawData
	binary.LittleEndian.PutUint32(buf[sec+20:], dataFileOff) // PointerToRawData

	// rdata 内的对象（用 RVA 表示，即相对 imageBase 的偏移）；中文按 GBK 编码。
	g1, _ := gbk.Encode("启动线程"); str1 := append(g1, 0)
	g2, _ := gbk.Encode("延时"); str2 := append(g2, 0)
	g3, _ := gbk.Encode("测试支持库"); libName := append(g3, 0)
	guid := []byte("12345678-1234-1234-1234-123456789012\x00")

	rvaToOff := func(rva uint32) int { return int(rva - rdataVA + dataFileOff) }
	putStr := func(rva uint32, s []byte) {
		o := rvaToOff(rva)
		copy(buf[o:], s)
	}
	// 分配字符串 RVA
	s1RVA, s2RVA := uint32(0x2100), uint32(0x2200)
	nameRVA, guidRVA := uint32(0x2300), uint32(0x2400)
	putStr(s1RVA, str1); putStr(s2RVA, str2); putStr(nameRVA, libName); putStr(guidRVA, guid)

	// CMD_INFO 数组 @ RVA 0x2500，每项 36 字节
	cmdRVA := uint32(0x2500)
	cmdOff := rvaToOff(cmdRVA)
	c0 := cmdOff
	c1 := cmdOff + 36
	binary.LittleEndian.PutUint32(buf[c0:], s1RVA) // m_szName
	binary.LittleEndian.PutUint32(buf[c1:], s2RVA)

	// LIB_INFO @ RVA 0x2600
	libRVA := uint32(0x2600)
	lo := rvaToOff(libRVA)
	binary.LittleEndian.PutUint32(buf[lo:], fneLibFormatVer) // magic
	binary.LittleEndian.PutUint32(buf[lo+4:], guidRVA)
	binary.LittleEndian.PutUint32(buf[lo+8:], 1)  // major > 0
	binary.LittleEndian.PutUint32(buf[lo+36:], nameRVA)
	binary.LittleEndian.PutUint32(buf[lo+100:], 2)  // m_nCmdCount
	binary.LittleEndian.PutUint32(buf[lo+104:], cmdRVA) // m_pBeginCmdInfo
	return buf
}

func TestLoadFneSynthetic(t *testing.T) {
	lib, err := LoadFne(buildFakeFne(), "fake.fne")
	if err != nil { t.Fatalf("LoadFne 失败: %v", err) }
	if lib.Count != 2 { t.Errorf("Count=%d, 期望 2", lib.Count) }
	if lib.Name != "测试支持库" { t.Errorf("Name=%q", lib.Name) }
	if lib.Guid != "12345678-1234-1234-1234-123456789012" { t.Errorf("Guid=%q", lib.Guid) }
	if lib.Commands[0] != "启动线程" { t.Errorf("cmd0=%q", lib.Commands[0]) }
	if lib.Commands[1] != "延时" { t.Errorf("cmd1=%q", lib.Commands[1]) }
}
