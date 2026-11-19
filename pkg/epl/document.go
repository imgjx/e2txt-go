package epl

import (
	"errors"
	"e2txt-go/pkg/gbk"
)

// Load 从 .e 文件字节解析出完整工程。
// 严格对应 EplDocument.Load + ProjectFileReader。
func Load(data []byte) (*EFile, error) {
	f := &EFile{}
	r := NewReader(data)

	// --- 文件头：magic1, magic2 ---
	magic1 := r.ReadUInt32()
	magic2 := r.ReadUInt32()
	cryptEC := false
	if magic1 == 0x454C5457 { // WTLE 加密
		switch magic2 {
		case 0x00000001, 0x00020001:
			return nil, errors.New("该文件已加密（WTLE），当前解析器不支持带密码源码")
		default:
			return nil, errors.New("不支持的加密类型")
		}
	}
	if magic1 != 0x54574E43 || magic2 != 0x47525045 { // CNWTEPRG
		return nil, errors.New("不是易语言工程文件（魔数不匹配）")
	}

	dec := Decoder(gbk.Decode)
	for {
		if r.Remaining() < 4 {
			break
		}
			raw, err := readSection(r, dec, cryptEC)
		if err != nil {
			return nil, err
		}
		raw.Index = int32(len(f.Sections) + 1)
		sec := &Section{Name: raw.Name, Key: raw.Key, Raw: raw.Data, Extra: raw}
		switch raw.Key {
		case SecSystemInfo:
			si, e := parseSystemInfo(raw.Data)
			if e != nil { return nil, e }
			sec.SysInfo, f.SystemInfo = si, si
			f.EncodingLanguage = si.Language
			dec = decoderForLanguage(si.Language)
		case SecCode:
			cs, e := parseCodeSection(raw.Data, dec, cryptEC)
			if e != nil { return nil, e }
			sec.Code, f.Code = cs, cs
		case SecResource:
			rs, e := parseResourceSection(raw.Data, dec)
			if e != nil { return nil, e }
			sec.Res, f.Resources = rs, rs
		}
		f.Sections = append(f.Sections, sec)
		if raw.Key == SecEOF {
			break
		}
	}
	return f, nil
}

// readSection 严格对应 ProjectFileReader.ReadSection。
func readSection(r *Reader, dec Decoder, cryptEC bool) (*RawSection, error) {
	if r.ReadInt32() != 0x15117319 {
		return nil, errors.New("段 Magic 错误")
	}
	headerCRC := r.ReadInt32() // InfoCheckSum
	key := r.ReadInt32()
	name := decodeName(key, r.ReadBytes(30))
	r.ReadInt16() // 对齐填充
	r.ReadInt32() // Index（文件内序号，写回时统一重排）
	isOptional := r.ReadInt32() != 0
	dataCRC := r.ReadInt32() // DataCheckSum
	dataLen := r.ReadInt32()
	if cryptEC {
		dataLen ^= 1
	}
	r.ReadBytes(40) // 保留
	data := r.ReadBytes(int(dataLen))
	return &RawSection{Key: key, Name: name, IsOptional: isOptional, Data: data,
		HeaderCRC: headerCRC, DataCRC: dataCRC}, nil
}

// decodeName 对应 ProjectFileReader.DecodeName。
func decodeName(key int32, encoded []byte) string {
	r := append([]byte(nil), encoded...)
	if key != 0x07007319 {
		kb := []byte{byte(key), byte(key >> 8), byte(key >> 16), byte(key >> 24)}
		for i := range r {
			r[i] ^= kb[(i+1)%4]
		}
	}
	if idx := indexByte(r, 0); idx != -1 {
		r = r[:idx]
	}
	return gbk.Decode(r)
}

func decoderForLanguage(lang int32) Decoder {
	// 样本几乎总是 GBK(1)。BIG5/SJIS 需额外表，先回退 GBK 保证多数情况可用。
	return gbk.Decode
}

// parseSystemInfo 对应 ESystemInfoSection.Parse。
func parseSystemInfo(data []byte) (*SystemInfo, error) {
	r := NewReader(data)
	s := &SystemInfo{}
	s.ESystemVersion = Version{r.ReadInt16(), r.ReadInt16()}
	r.ReadInt32()
	s.Language = r.ReadInt32()
	s.EProjectFormatVer = Version{r.ReadInt16(), r.ReadInt16()}
	s.FileType = r.ReadInt32()
	r.ReadInt32()
	s.ProjectType = r.ReadInt32()
	return s, nil
}

// parseCodeSection 对应 CodeSection.Parse。
func parseCodeSection(data []byte, dec Decoder, cryptEC bool) (*CodeSection, error) {
	r := NewReader(data)
	cs := &CodeSection{}
	cs.AllocatedIDNum = r.ReadInt32()
	r.ReadInt32() // 51113791
	minCmds := r.ReadInt32sWithByteSizePrefix()
	var minTypes, minConsts []int16
	if cryptEC {
		r.ReadInt32(); r.ReadInt32()
		minTypes = r.ReadInt16sWithByteSizePrefix()
		cs.Flag = r.ReadInt32()
		cs.MainMethod = r.ReadInt32()
		cs.Libraries = readLibraries(r, dec)
		minConsts = r.ReadInt16sWithByteSizePrefix()
	} else {
		minTypes = r.ReadInt16sWithByteSizePrefix()
		minConsts = r.ReadInt16sWithByteSizePrefix()
		cs.Libraries = readLibraries(r, dec)
		cs.Flag = r.ReadInt32()
		cs.MainMethod = r.ReadInt32()
	}
	applyCompat(cs.Libraries, minCmds, minTypes, minConsts)
	if cs.Flag&1 != 0 {
		r.ReadBytes(16)
	}
	cs.IconData = r.ReadBytesWithLengthPrefix()
	cs.DebugParams = r.ReadStringWithLengthPrefix(dec)
	if cryptEC {
		r.ReadBytes(12)
		cs.Methods = readMethods(r, dec)
		cs.DllDeclares = readDllDeclares(r, dec)
		cs.GlobalVars = readVariables(r, dec, "global")
		cs.Classes = readClasses(r, dec)
		cs.Structs = readStructs(r, dec)
	} else {
		cs.Classes = readClasses(r, dec)
		cs.Methods = readMethods(r, dec)
		cs.GlobalVars = readVariables(r, dec, "global")
		cs.Structs = readStructs(r, dec)
		cs.DllDeclares = readDllDeclares(r, dec)
	}
	return cs, nil
}

func readLibraries(r *Reader, dec Decoder) []*LibraryRef {
	strs := r.ReadStringsAsList(dec)
	out := make([]*LibraryRef, 0, len(strs))
	for _, s := range strs {
		parts := splitAll(s, '\r')
		if len(parts) < 5 { continue }
		lib := &LibraryRef{FileName: parts[0], GuidString: parts[1], Name: parts[4]}
		lib.VersionMajor = atoi(parts[2])
		lib.VersionMinor = atoi(parts[3])
		out = append(out, lib)
	}
	return out
}

func applyCompat(libs []*LibraryRef, cmds []int32, types, consts []int16) {
	for i, l := range libs {
		if i < len(cmds) { l.MinRequiredCmd = cmds[i] }
		if i < len(types) { l.MinRequiredType = types[i] }
		if i < len(consts) { l.MinRequiredConst = consts[i] }
	}
}

// readClasses 对应 ClassInfo.ReadClasses（ReadBlocksWithIdAndMemoryAddress）。
func readClasses(r *Reader, dec Decoder) []*ClassInfo {
	var out []*ClassInfo
	r.ReadBlocksWithIDAndMemAddr(func(er *Reader, id, mem int32) {
		c := &ClassInfo{ID: id, MemoryAddr: mem}
		c.Form = er.ReadInt32()
		c.BaseClass = er.ReadInt32()
		c.Name = er.ReadStringWithLengthPrefix(dec)
		c.Comment = er.ReadStringWithLengthPrefix(dec)
		c.Methods = er.ReadInt32sFixed(int(er.ReadInt32()) / 4)
		c.Variables = readVariables(er, dec, "class")
		out = append(out, c)
	})
	return out
}

// readMethods 对应 MethodInfo.ReadMethods。
func readMethods(r *Reader, dec Decoder) []*MethodInfo {
	var out []*MethodInfo
	r.ReadBlocksWithIDAndMemAddr(func(er *Reader, id, mem int32) {
		m := &MethodInfo{ID: id, MemoryAddr: mem}
		m.Class = er.ReadInt32()
		m.Flags = er.ReadInt32()
		m.ReturnDataType = er.ReadInt32()
		m.Name = er.ReadStringWithLengthPrefix(dec)
		m.Comment = er.ReadStringWithLengthPrefix(dec)
		m.Variables = readVariables(er, dec, "local")
		m.Parameters = readVariables(er, dec, "param")
		m.Code = MethodCodeData{
			LineOffset: er.ReadBytesWithLengthPrefix(),
			BlockOffset: er.ReadBytesWithLengthPrefix(),
			MethodRef: er.ReadBytesWithLengthPrefix(),
			VariableRef: er.ReadBytesWithLengthPrefix(),
			ConstantRef: er.ReadBytesWithLengthPrefix(),
			ExpressionData: er.ReadBytesWithLengthPrefix(),
		}
		out = append(out, m)
	})
	return out
}

// readDllDeclares 对应 DllDeclareInfo.ReadDllDeclares。
func readDllDeclares(r *Reader, dec Decoder) []*DllDeclareInfo {
	var out []*DllDeclareInfo
	r.ReadBlocksWithIDAndMemAddr(func(er *Reader, id, mem int32) {
		d := &DllDeclareInfo{ID: id}
		d.Flags = er.ReadInt32()
		d.ReturnDataType = er.ReadInt32()
		d.Name = er.ReadStringWithLengthPrefix(dec)
		d.Comment = er.ReadStringWithLengthPrefix(dec)
		d.LibraryName = er.ReadStringWithLengthPrefix(dec)
		d.EntryPoint = er.ReadStringWithLengthPrefix(dec)
		d.Parameters = readVariables(er, dec, "dllparam")
		out = append(out, d)
	})
	return out
}

// readStructs 对应 StructInfo.ReadStructs。
func readStructs(r *Reader, dec Decoder) []*StructInfo {
	var out []*StructInfo
	r.ReadBlocksWithIDAndMemAddr(func(er *Reader, id, mem int32) {
		s := &StructInfo{ID: id}
		s.Flags = er.ReadInt32()
		s.Name = er.ReadStringWithLengthPrefix(dec)
		s.Comment = er.ReadStringWithLengthPrefix(dec)
		s.Members = readVariables(er, dec, "structmember")
		out = append(out, s)
	})
	return out
}

// readVariables 对应 AbstractVariableInfo.ReadVariables（ReadBlocksWithIdAndOffest）。
func readVariables(r *Reader, dec Decoder, kind string) []*VariableInfo {
	var out []*VariableInfo
	r.ReadBlocksWithIDAndOffset(func(er *Reader, id int32) {
		v := &VariableInfo{ID: id, Kind: kind}
		v.DataType = er.ReadInt32()
		v.Flags = er.ReadInt16()
		v.UBound = er.ReadInt32sFixed(int(er.ReadByte()))
		v.Name = er.ReadCStyleString(dec)
		v.Comment = er.ReadCStyleString(dec)
		out = append(out, v)
	})
	return out
}

// parseResourceSection 对应 ResourceSection.Parse = Forms + Constants。
func parseResourceSection(data []byte, dec Decoder) (*ResourceSection, error) {
	r := NewReader(data)
	rs := &ResourceSection{}
	rs.Forms = readForms(r, dec)
	rs.Constants = readConstants(r, dec)
	return rs, nil
}

func readForms(r *Reader, dec Decoder) []*FormInfo {
	var out []*FormInfo
	r.ReadBlocksWithIDAndMemAddr(func(er *Reader, id, mem int32) {
		fm := &FormInfo{ID: id, MemoryAddr: mem}
		fm.UnknownBeforeCls = er.ReadInt32()
		fm.Class = er.ReadInt32()
		fm.Name = er.ReadStringWithLengthPrefix(dec)
		fm.Comment = er.ReadStringWithLengthPrefix(dec)
		fm.Elements = readFormElements(er, dec)
		out = append(out, fm)
	})
	return out
}

// readFormElements 对应 FormElementInfo.ReadFormElements。
// dataType==65539 为菜单，否则为控件；此处保留公共字段与原始细节字节。
func readFormElements(r *Reader, dec Decoder) []*FormElement {
	var out []*FormElement
	r.ReadBlocksWithIDAndOffset(func(er *Reader, id int32) {
		dataType := er.ReadInt32()
		e := &FormElement{ID: id, DataType: dataType, IsMenu: dataType == 65539}
		// FormControlInfo / FormMenuInfo 公共头：20 字节未知 + CStyleString 名称。
		start := er.Pos
		er.ReadBytes(20)
		e.Name = er.ReadCStyleString(dec) // 名称
		er.ReadCStyleString(dec)          // 注释（菜单无注释，同样占位）
		e.RawDetail = er.Data[start:er.Pos]
		out = append(out, e)
	})
	return out
}

// readConstants 对应 ConstantInfo.ReadConstants。
func readConstants(r *Reader, dec Decoder) []*ConstantInfo {
	var out []*ConstantInfo
	r.ReadBlocksWithIDAndOffset(func(er *Reader, id int32) {
		c := &ConstantInfo{ID: id}
		c.Flags = er.ReadInt16()
		c.Name = er.ReadCStyleString(dec)
		c.Comment = er.ReadCStyleString(dec)
		kind := uint32(id) >> 28
		switch kind {
		case 1: // 常量
			t := er.ReadByte()
			switch t {
			case 22:
				c.Value, c.ValueKind = nil, "null"
			case 23:
				c.Value, c.ValueKind = er.ReadDouble(), "number"
			case 24:
				c.Value, c.ValueKind = er.ReadInt32() != 0, "bool"
			case 25:
				c.Value, c.ValueKind = er.ReadDouble(), "date"
			case 26:
				c.Value, c.ValueKind = er.ReadBStr(dec), "string"
			}
		case 2, 3: // 图片 / 声音
			c.Value, c.ValueKind = er.ReadBytesWithLengthPrefix(), "resource"
		}
		c.IsLongText = c.Flags&0x10 != 0
		out = append(out, c)
	})
	return out
}

// ---------- 小工具 ----------

func splitAll(s string, sep rune) []string {
	var out []string
	cur := []rune{}
	for _, c := range s {
		if c == sep { out = append(out, string(cur)); cur = cur[:0] } else { cur = append(cur, c) }
	}
	out = append(out, string(cur))
	return out
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' { break }
		n = n*10 + int(c-'0')
	}
	return n
}
