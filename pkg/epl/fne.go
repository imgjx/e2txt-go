package epl

import (
	"encoding/binary"
	"errors"
	"strings"

	"e2txt-go/pkg/gbk"
)

// 本文件静态解析易语言支持库文件（.fne / .fnr，本质是 32 位 Windows PE DLL），
// 直接提取「命令序号 -> 命令名」表，无需在 Windows 上 LoadLibrary 调用 GetNewInf。
//
// 原理：
//   .fne 内编译期静态存放了一个 LIB_INFO 结构，其首个字段 m_dwLibFormatVer
//   固定为 LIB_FORMAT_VER = 20000101 = 0x01312D65，可据此在 .rdata 中定位。
//   LIB_INFO 的 m_nCmdCount（+100）与 m_pBeginCmdInfo（+104）指向 CMD_INFO 数组，
//   每个 CMD_INFO 首字段 m_szName 是指向 GBK 命令名的指针。
//   CMD_INFO 数组下标即 .e 字节码里引用的「命令号」，二者一一对应。
//
// PE 中这些指针既可能是 RVA（相对映像基址），也可能是 VA（ImageBase+RVA），
// 解析时对每种候选做探测，取落在有效节内且能读出合法 GBK 名称的解释。

const (
	fneLibFormatVer = uint32(0x01312D65) // LIB_FORMAT_VER = 20000101
	fneCmdInfoSize  = 36                 // x86 CMD_INFO 结构大小
)

// FneLib 是从一个 .fne/.fnr 提取出的支持库命令表。
type FneLib struct {
	Name     string            // 支持库中文名（来自 LIB_INFO.m_szName）
	Guid     string            // GUID（来自 m_szGuid）
	FileName string            // 文件名（外部传入）
	Commands map[int32]string  // 命令序号 -> 中文命令名
	Count    int               // 命令总数 m_nCmdCount
}

// peImage 保存解析 PE 所需的节表信息。
type peImage struct {
	data       []byte
	imageBase  uint32
	sections   []peSection
}

type peSection struct {
	virtAddr   uint32 // 节 RVA
	virtSize   uint32 // 节虚拟大小
	rawOffset  uint32 // 节在文件中的偏移
	rawSize    uint32 // 节在文件中的大小
}

func (im *peImage) u16(off int) uint16 {
	if off < 0 || off+2 > len(im.data) { return 0 }
	return binary.LittleEndian.Uint16(im.data[off:])
}
func (im *peImage) u32(off int) uint32 {
	if off < 0 || off+4 > len(im.data) { return 0 }
	return binary.LittleEndian.Uint32(im.data[off:])
}

// rvaToOffset 把 RVA 转换为文件偏移。
func (im *peImage) rvaToOffset(rva uint32) (int, bool) {
	for _, s := range im.sections {
		size := s.virtSize
		if s.rawSize > size { size = s.rawSize }
		if rva >= s.virtAddr && rva < s.virtAddr+size {
			off := int(s.rawOffset + (rva - s.virtAddr))
			if off >= 0 && off < len(im.data) { return off, true }
		}
	}
	return 0, false
}

// cstringAt 从文件偏移读一个以 NUL 结尾的 GBK/ASCII 字符串。
func (im *peImage) cstringAt(off int, max int) string {
	if off < 0 || off >= len(im.data) { return "" }
	end := off
	limit := off + max
	if limit > len(im.data) { limit = len(im.data) }
	for end < limit && im.data[end] != 0 { end++ }
	return gbk.Decode(im.data[off:end])
}

// readPE 解析 DOS/PE 头，建立节表。
func readPE(data []byte) (*peImage, error) {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return nil, errors.New("不是有效的 PE/DLL 文件（缺少 MZ 头）")
	}
	peOff := int(binary.LittleEndian.Uint32(data[0x3C:]))
	if peOff <= 0 || peOff+24 > len(data) || string(data[peOff:peOff+4]) != "PE\x00\x00" {
		return nil, errors.New("缺少 PE 签名")
	}
	im := &peImage{data: data}
	numSections := int(im.u16(peOff + 6))
	optSize := int(im.u16(peOff + 20))
	optOff := peOff + 24
	if optOff+optSize > len(data) { return nil, errors.New("可选头越界") }
	magic := im.u16(optOff)
	var imageBase uint32
	switch magic {
	case 0x10b: // PE32
		imageBase = im.u32(optOff + 28)
	case 0x20b: // PE32+
		imageBase = uint32(im.u64(optOff + 24))
	default:
		return nil, errors.New("未知的可选头 magic")
	}
	im.imageBase = imageBase
	secOff := optOff + optSize
	for i := 0; i < numSections; i++ {
		o := secOff + i*40
		if o+40 > len(data) { break }
		im.sections = append(im.sections, peSection{
			virtAddr:  im.u32(o + 12),
			virtSize:  im.u32(o + 8),
			rawSize:   im.u32(o + 16),
			rawOffset: im.u32(o + 20),
		})
	}
	return im, nil
}

func (im *peImage) u64(off int) uint64 {
	if off < 0 || off+8 > len(im.data) { return 0 }
	return binary.LittleEndian.Uint64(im.data[off:])
}

// ptrCString 尝试把一个指针值（RVA 或 VA）解析为可读 GBK 字符串。
func (im *peImage) ptrCString(ptr uint32) string {
	cands := []uint32{ptr} // RVA 解释
	if ptr >= im.imageBase { cands = append(cands, ptr-im.imageBase) } // VA 解释
	for _, rva := range cands {
		if off, ok := im.rvaToOffset(rva); ok {
			s := im.cstringAt(off, 256)
			if s != "" && validCmdName(s) { return s }
		}
	}
	return ""
}

// validCmdName 粗判一个字符串是否像命令名（排除二进制乱码）。
func validCmdName(s string) bool {
	if s == "" || len(s) > 64 { return false }
	for _, r := range s {
		if r == 0 { return false }
		// 允许中日韩文字、ASCII 可见字符、常见符号
		if r < 0x20 && r != '\t' { return false }
	}
	return true
}

// readPtr 按 candidate RVA 读取一个 4 字节值（返回原始 uint32）。
func (im *peImage) readStructField(libOff int, fieldOff int) uint32 {
	return im.u32(libOff + fieldOff)
}

// LoadFne 静态解析 .fne/.fnr 字节，提取命令表。
func LoadFne(data []byte, fileName string) (*FneLib, error) {
	im, err := readPE(data)
	if err != nil { return nil, err }

	// 扫描 LIB_INFO.m_dwLibFormatVer magic。
	magicBytes := []byte{0x65, 0x2D, 0x31, 0x01} // 0x01312D65 little-endian
	libOff := -1
	for i := 0; i+4 <= len(data); i++ {
		if data[i] == magicBytes[0] && data[i+1] == magicBytes[1] &&
			data[i+2] == magicBytes[2] && data[i+3] == magicBytes[3] {
			// 粗校验：m_nMajorVersion(off+8) 应 >0，m_szName(off+36) 指针非0
			if im.u32(i+8) > 0 && im.u32(i+36) != 0 {
				libOff = i
				break
			}
		}
	}
	if libOff < 0 { return nil, errors.New("未找到 LIB_INFO（magic 0x01312D65）") }

	lib := &FneLib{FileName: fileName, Commands: map[int32]string{}}
	lib.Name = im.ptrCString(im.readStructField(libOff, 36))
	lib.Guid = im.ptrCString(im.readStructField(libOff, 4))

	cmdCount := int32(im.readStructField(libOff, 100))
	if cmdCount <= 0 || cmdCount > 100000 { return lib, nil } // 无命令，仍返回库名
	lib.Count = int(cmdCount)

	cmdPtr := im.readStructField(libOff, 104) // m_pBeginCmdInfo
	// 解析 CMD_INFO 数组基址的文件偏移。
	baseOff, ok := im.commandArrayOffset(cmdPtr)
	if !ok { return lib, nil }

	for i := int32(0); i < cmdCount; i++ {
		entryOff := baseOff + int(i)*fneCmdInfoSize
		if entryOff+fneCmdInfoSize > len(data) { break }
		namePtr := im.u32(entryOff) // m_szName
		name := im.ptrCString(namePtr)
		if name != "" { lib.Commands[i] = name }
	}
	return lib, nil
}

// commandArrayOffset 把 CMD_INFO 数组指针转换为文件偏移。
func (im *peImage) commandArrayOffset(ptr uint32) (int, bool) {
	cands := []uint32{ptr}
	if ptr >= im.imageBase { cands = append(cands, ptr-im.imageBase) }
	for _, rva := range cands {
		if off, ok := im.rvaToOffset(rva); ok {
			// 校验：首个 CMD_INFO.m_szName 应能解析出命令名
			if off+fneCmdInfoSize <= len(im.data) {
				name := im.ptrCString(im.u32(off))
				if name != "" { return off, true }
			}
		}
	}
	return 0, false
}

// libCmdTablesFromFne 全局注册：由外部 .fne 载入的命令表，按多种键索引。
var fneLibs []*FneLib

// RegisterFne 注册一个或多个 .fne 解析出的库，供命令名还原使用。
func RegisterFne(libs ...*FneLib) { fneLibs = append(fneLibs, libs...) }

// ResetFne 清空已注册的 .fne 库（用于测试或重复加载）。
func ResetFne() { fneLibs = nil }

// lookupFneCommand 从已注册 .fne 库中按命令号查命令名。
func lookupFneCommand(lib *LibraryRef, methodID int32) string {
	if lib == nil || len(fneLibs) == 0 { return "" }
	guid := strings.ToLower(strings.TrimSpace(lib.GuidString))
	name := strings.TrimSpace(lib.Name)
	file := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(lib.FileName, ".fnr"), ".fne"))
	for _, fl := range fneLibs {
		matched := false
		if fl.Guid != "" && guid != "" && strings.EqualFold(fl.Guid, guid) { matched = true }
		if !matched && fl.Name != "" && fl.Name == name { matched = true }
		if !matched && fl.FileName != "" {
			fbase := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(fl.FileName, ".fnr"), ".fne"))
			if fbase == file { matched = true }
		}
		if matched {
			if v, ok := fl.Commands[methodID]; ok { return v }
		}
	}
	return ""
}
