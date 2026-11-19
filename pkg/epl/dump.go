package epl

import (
	"encoding/json"
	"fmt"
)

// DumpJSON 把解析结果导出为可读 JSON（用于逆向验证与查看）。
func DumpJSON(f *EFile, pretty bool) ([]byte, error) {
	d := struct {
		FileType      string          `json:"file_type"`
		SystemVersion string          `json:"system_version"`
		Language      int32           `json:"language_code"`
		Sections      []sectionDump   `json:"sections"`
		Libraries     []*LibraryRef   `json:"libraries,omitempty"`
		Classes       []*ClassInfo    `json:"classes,omitempty"`
		Methods       []methodDump    `json:"methods,omitempty"`
		GlobalVars    []*VariableInfo `json:"global_variables,omitempty"`
		Structs       []*StructInfo   `json:"structs,omitempty"`
		DllDeclares   []*DllDeclareInfo `json:"dll_declares,omitempty"`
		Constants     []*ConstantInfo `json:"constants,omitempty"`
		Forms         []*FormInfo     `json:"forms,omitempty"`
	}{
		FileType: "易语言工程 (.e)",
	}
	if f.SystemInfo != nil {
		d.SystemVersion = fmt.Sprintf("%d.%d", f.SystemInfo.ESystemVersion.Major, f.SystemInfo.ESystemVersion.Minor)
		d.Language = f.SystemInfo.Language
	}
	for _, s := range f.Sections {
		d.Sections = append(d.Sections, sectionDump{Name: s.Name, Key: fmt.Sprintf("0x%08X", uint32(s.Key)), DataLen: len(s.Raw)})
	}
	if f.Code != nil {
		d.Libraries, d.Classes, d.GlobalVars, d.Structs, d.DllDeclares = f.Code.Libraries, f.Code.Classes, f.Code.GlobalVars, f.Code.Structs, f.Code.DllDeclares
		for _, m := range f.Code.Methods {
			stmts, err := ParseStatementBlock(m.Code.ExpressionData, decoderForLanguage(f.EncodingLanguage))
			d.Methods = append(d.Methods, methodDump{
				ID: m.ID, Name: m.Name, Class: m.Class, ReturnType: m.ReturnDataType,
				Public: m.IsPublic(), ParamCount: len(m.Parameters), LocalCount: len(m.Variables),
				CodeLen: len(m.Code.ExpressionData), Statements: len(stmts), DecodeErr: errString(err),
			})
		}
	}
	if f.Resources != nil {
		d.Constants, d.Forms = f.Resources.Constants, f.Resources.Forms
	}
	if pretty {
		return json.MarshalIndent(d, "", "  ")
	}
	return json.Marshal(d)
}

type sectionDump struct {
	Name    string `json:"name"`
	Key     string `json:"key"`
	DataLen int    `json:"data_length"`
}

type methodDump struct {
	ID          int32  `json:"id"`
	Name        string `json:"name"`
	Class       int32  `json:"class_id"`
	ReturnType  int32  `json:"return_type"`
	Public      bool   `json:"public"`
	ParamCount  int    `json:"param_count"`
	LocalCount  int    `json:"local_count"`
	CodeLen     int    `json:"code_length"`
	Statements  int    `json:"statements"`
	DecodeErr   string `json:"decode_error,omitempty"`
}

func errString(e error) string { if e != nil { return e.Error() }; return "" }
