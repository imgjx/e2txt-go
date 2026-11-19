package epl

// 本文件定义 .e 工程的结构化数据模型。

// RawSection 是未解析的原始段（对应 RawSectionInfo）。
type RawSection struct {
	Name       string
	Key        int32
	Data       []byte
	IsOptional bool
	Index      int32  // 段序号（写回时按出现顺序重新赋值）
	HeaderCRC  int32  // 原始头校验和（用于校验解析一致性）
	DataCRC    int32  // 原始数据校验和
}

// EFile 是一份完整的易语言工程（对应 EplDocument）。
type EFile struct {
	Sections         []*Section
	SystemInfo       *SystemInfo
	Code             *CodeSection
	Resources        *ResourceSection
	EncodingLanguage int32
}

// Section 是解析后的段（用 Key 区分具体类型）。
type Section struct {
	Name    string
	Key     int32
	Raw     []byte
	Code    *CodeSection
	Res     *ResourceSection
	SysInfo *SystemInfo
	Extra   *RawSection
}

// SystemInfo 对应 ESystemInfoSection。
type SystemInfo struct {
	ESystemVersion      Version
	Language            int32
	EProjectFormatVer   Version
	FileType            int32
	ProjectType         int32
}

type Version struct{ Major, Minor int16 }

// LibraryRef 对应 LibraryRefInfo。
type LibraryRef struct {
	FileName         string
	GuidString       string
	VersionMajor     int
	VersionMinor     int
	Name             string
	MinRequiredCmd   int32
	MinRequiredType  int16
	MinRequiredConst int16
}

// CodeSection 对应 CodeSection。
type CodeSection struct {
	AllocatedIDNum int32
	Libraries      []*LibraryRef
	Flag           int32
	MainMethod     int32
	IconData       []byte
	DebugParams    string
	Classes        []*ClassInfo
	Methods        []*MethodInfo
	GlobalVars     []*VariableInfo
	Structs        []*StructInfo
	DllDeclares    []*DllDeclareInfo
}

// ResourceSection 对应 ResourceSection。
type ResourceSection struct {
	Forms     []*FormInfo
	Constants []*ConstantInfo
}

// VariableInfo 对应 AbstractVariableInfo（所有变量/参数/成员的公共结构）。
type VariableInfo struct {
	ID       int32
	DataType int32
	Flags    int16
	UBound   []int32
	Name     string
	Comment  string
	Kind     string // global/class/local/param/dllparam/structmember
}

// ClassInfo 对应 ClassInfo。
type ClassInfo struct {
	ID           int32
	MemoryAddr   int32
	Form         int32
	BaseClass    int32
	Name         string
	Comment      string
	Methods      []int32
	Variables    []*VariableInfo
}

// MethodCodeData 对应 MethodCodeData（6 段长度前缀字节数组）。
type MethodCodeData struct {
	LineOffset, BlockOffset, MethodRef, VariableRef, ConstantRef, ExpressionData []byte
}

// MethodInfo 对应 MethodInfo。
type MethodInfo struct {
	ID             int32
	MemoryAddr     int32
	Class          int32
	Flags          int32
	ReturnDataType int32
	Name           string
	Comment        string
	Variables      []*VariableInfo
	Parameters     []*VariableInfo
	Code           MethodCodeData
}

// DllDeclareInfo 对应 DllDeclareInfo。
type DllDeclareInfo struct {
	ID             int32
	Flags          int32
	ReturnDataType int32
	Name           string
	Comment        string
	LibraryName    string
	EntryPoint     string
	Parameters     []*VariableInfo
}

// StructInfo 对应 StructInfo。
type StructInfo struct {
	ID      int32
	Flags   int32
	Name    string
	Comment string
	Members []*VariableInfo
}

// ConstantInfo 对应 ConstantInfo。Value 的类型见 ConstantInfo.cs：
// nil / string / bool / float64 / []byte / OADate(float64) with Type 标记。
type ConstantInfo struct {
	ID       int32
	Flags    int16
	Name     string
	Comment  string
	Value    interface{}
	ValueKind string // null/number/bool/date/string/resource
	IsLongText bool
}

// FormInfo 对应 FormInfo。
type FormInfo struct {
	ID               int32
	MemoryAddr       int32
	UnknownBeforeCls int32
	Class            int32
	Name             string
	Comment          string
	Elements         []*FormElement
}

// FormElement 对应 FormElementInfo（控件或菜单的简化模型）。
type FormElement struct {
	ID          int32
	DataType    int32
	Name        string
	Visible     bool
	Disable     bool
	IsMenu      bool
	RawDetail   []byte
}

// ---------- 标志位辅助 ----------

func (m *MethodInfo) IsPublic() bool  { return m.Flags&0x8 != 0 }
func (m *MethodInfo) IsHidden() bool  { return m.Flags&0x80 != 0 }
func (d *DllDeclareInfo) IsPublic() bool { return d.Flags&0x2 != 0 }
func (s *StructInfo) IsPublic() bool  { return s.Flags&0x1 != 0 }
func (c *ConstantInfo) IsPublic() bool { return c.Flags&0x2 != 0 }
func (c *ConstantInfo) IsLong() bool  { return c.Flags&0x10 != 0 }

// GetType 对应 EplSystemId.GetType。
func GetType(id int32) int32 { return int32(uint32(id) & uint32(0xFF000000)) }
func IsLibDataType(id int32) bool { return (uint32(id) & uint32(0xFF000000)) == 0 && id != 0 }

// 已知段 key。
const (
	SecConfig       int32 = 0x01007319
	SecSystemInfo   int32 = 0x02007319
	SecCode         int32 = 0x03007319
	SecResource     int32 = 0x04007319
	SecLosable      int32 = 0x05007319
	SecEOF          int32 = 0x07007319
	SecInitEC       int32 = 0x08007319
	SecEditorInfo   int32 = 0x09007319
	SecEventIndices int32 = 0x0A007319
	SecClassPublic  int32 = 0x0B007319
	SecECDeps       int32 = 0x0C007319
	SecPackageInfo  int32 = 0x0D007319
	SecFolder       int32 = 0x0E007319
	SecCondComp     int32 = 0x11007319
	SecConfigEx     int32 = 0x10007319
)
