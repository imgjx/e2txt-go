package epl

import (
	"fmt"
	"strings"
	"time"

	"e2txt-go/pkg/gbk"
)

// 本文件把结构化模型还原为易语言文本代码。

// NameMap 负责把 ID 映射到可读名称（对应 IdToNameMap 的简化版）。
type NameMap struct {
	methods   map[int32]string
	vars      map[int32]string
	consts    map[int32]string
	classes   map[int32]string
	libs      []*LibraryRef
	structs   map[int32]string
	dlls      map[int32]string // DLL命令 ID -> 名称
}

func NewNameMap(f *EFile) *NameMap {
	nm := &NameMap{
		methods: map[int32]string{}, vars: map[int32]string{},
		consts: map[int32]string{}, classes: map[int32]string{}, structs: map[int32]string{},
		dlls: map[int32]string{},
	}
	if f.Code == nil { return nm }
	nm.libs = f.Code.Libraries
	for _, d := range f.Code.DllDeclares { nm.dlls[d.ID] = d.Name }
	for _, m := range f.Code.Methods { nm.methods[m.ID] = m.Name }
	for _, c := range f.Code.Classes { nm.classes[c.ID] = c.Name }
	for _, s := range f.Code.Structs { nm.structs[s.ID] = s.Name }
	addVars := func(vs []*VariableInfo) { for _, v := range vs { nm.vars[v.ID] = v.Name } }
	addVars(f.Code.GlobalVars)
	for _, m := range f.Code.Methods { addVars(m.Variables); addVars(m.Parameters) }
	for _, c := range f.Code.Classes { addVars(c.Variables) }
	for _, d := range f.Code.DllDeclares { addVars(d.Parameters) }
	for _, s := range f.Code.Structs { addVars(s.Members) }
	if f.Resources != nil {
		for _, c := range f.Resources.Constants { nm.consts[c.ID] = c.Name }
		// 窗口与控件 ID 纳入名称映射，提升字节码还原可读性。
		for _, w := range f.Resources.Forms {
			nm.methods[w.ID] = w.Name
			for _, e := range w.Elements {
				if e.Name != "" { nm.vars[e.ID] = e.Name }
			}
		}
	}
	return nm
}

func (nm *NameMap) name(id int32) string {
	if v, ok := nm.methods[id]; ok { return v }
	if v, ok := nm.vars[id]; ok { return v }
	if v, ok := nm.consts[id]; ok { return v }
	if v, ok := nm.classes[id]; ok { return v }
	if v, ok := nm.structs[id]; ok { return v }
	if v, ok := nm.dlls[id]; ok { return v }
	return fmt.Sprintf("__标识_%08X", uint32(id))
}

// libCommandName 还原支持库命令名：优先用内置命令表查真实名称，
// 未收录的命令退化为「支持库名.命令#N」占位。
func (nm *NameMap) libCommandName(libID, methodID int32) string {
	if libID >= 0 && int(libID) < len(nm.libs) {
		lib := nm.libs[libID]
		if real := lookupLibCommand(lib, methodID); real != "" {
			return real
		}
		return fmt.Sprintf("%s.命令#%d", lib.Name, methodID)
	}
	return fmt.Sprintf("支持库命令#%d", methodID)
}

// dataTypeName 对应 IdToNameMap.GetDataTypeName。
func (nm *NameMap) dataTypeName(dt int32) string {
	switch uint32(dt) {
	case 0x00000000: return ""
	case 0x80000000: return "通用型"
	case 0x80000101: return "字节型"
	case 0x80000201: return "短整数型"
	case 0x80000301: return "整数型"
	case 0x80000401: return "长整数型"
	case 0x80000501: return "小数型"
	case 0x80000601: return "双精度小数型"
	case 0x80000002: return "逻辑型"
	case 0x80000003: return "日期时间型"
	case 0x80000004: return "文本型"
	case 0x80000005: return "字节集"
	case 0x80000006: return "子程序指针"
	}
	if v, ok := nm.structs[dt]; ok { return v }
	return fmt.Sprintf("数据类型_%08X", uint32(dt))
}

// operatorMap 对应 CallExpression.OperatorMap。
var operatorMap = map[int32]struct{ sym string; prec, kind int }{
	15: {"*", 2, 2}, 16: {"/", 2, 2}, 17: {"\\", 3, 2}, 18: {"%", 4, 2},
	19: {"+", 5, 2}, 20: {"-", 5, 2}, 21: {"-", 1, 1},
	38: {"==", 6, 3}, 39: {"!=", 6, 3}, 40: {"<", 6, 3}, 41: {">", 6, 3},
	42: {"<=", 6, 3}, 43: {">=", 6, 3}, 44: {"?=", 6, 3},
	45: {"&&", 7, 2}, 46: {"||", 8, 2}, 52: {"=", 9, 3},
}

// GenerateText 生成完整的易语言源码文本。
func GenerateText(f *EFile) string {
	nm := NewNameMap(f)
	var b strings.Builder
	if f.Resources != nil && len(f.Resources.Constants) > 0 {
		b.WriteString("' ============ 常量 ============\n")
		for _, c := range f.Resources.Constants {
			b.WriteString("常量 " + c.Name + " = " + constValue(c, nm) + "\n")
		}
		b.WriteString("\n")
	}
	if f.Code == nil { return b.String() }
	cs := f.Code
	if len(cs.Libraries) > 0 {
		b.WriteString("' ============ 支持库引用 ============\n")
		for _, l := range cs.Libraries {
			fmt.Fprintf(&b, "' 支持库: %s  {%s}  v%d.%d\n", l.Name, l.GuidString, l.VersionMajor, l.VersionMinor)
		}
		b.WriteString("\n")
	}
	// 结构体
	if len(cs.Structs) > 0 {
		b.WriteString("' ============ 数据类型 ============\n")
		for _, s := range cs.Structs {
			fmt.Fprintf(&b, ".数据类型 %s\n", s.Name)
			for _, m := range s.Members {
				fmt.Fprintf(&b, "    .成员 %s, %s\n", m.Name, nm.dataTypeName(m.DataType))
			}
			b.WriteString("\n")
		}
	}
	// DLL 命令
	if len(cs.DllDeclares) > 0 {
		b.WriteString("' ============ DLL命令 ============\n")
		for _, d := range cs.DllDeclares {
			fmt.Fprintf(&b, ".DLL命令 %s, %s, \"%s\", \"%s\"\n", d.Name, nm.dataTypeName(d.ReturnDataType), d.LibraryName, d.EntryPoint)
			for _, p := range d.Parameters {
				fmt.Fprintf(&b, "    .参数 %s, %s\n", p.Name, nm.dataTypeName(p.DataType))
			}
			b.WriteString("\n")
		}
	}
	// 程序集 + 方法
	methodsByClass := map[int32][]*MethodInfo{}
	methodByID := map[int32]*MethodInfo{}
	for _, m := range cs.Methods { methodByID[m.ID] = m }
	for _, c := range cs.Classes {
		for _, mid := range c.Methods {
			if m, ok := methodByID[mid]; ok { methodsByClass[c.ID] = append(methodsByClass[c.ID], m) }
		}
	}
	// 未挂到任何程序集的方法
	assigned := map[int32]bool{}
	for _, ms := range methodsByClass { for _, m := range ms { assigned[m.ID] = true } }
	var orphan []*MethodInfo
	for _, m := range cs.Methods { if !assigned[m.ID] { orphan = append(orphan, m) } }

	for _, c := range cs.Classes {
		fmt.Fprintf(&b, "程序集 %s\n", c.Name)
		for _, v := range c.Variables {
			fmt.Fprintf(&b, "    .程序集变量 %s, %s\n", v.Name, nm.dataTypeName(v.DataType))
		}
		for _, m := range methodsByClass[c.ID] {
			b.WriteString("\n")
			writeMethod(&b, m, nm)
		}
		b.WriteString("\n")
	}
	if len(orphan) > 0 {
		b.WriteString("' ============ 独立子程序 ============\n")
		for _, m := range orphan { writeMethod(&b, m, nm); b.WriteString("\n") }
	}
	return b.String()
}

func writeMethod(b *strings.Builder, m *MethodInfo, nm *NameMap) {
	pub := ""
	if m.IsPublic() { pub = ", 公开" }
	ret := nm.dataTypeName(m.ReturnDataType)
	if ret != "" { ret = ", " + ret }
	fmt.Fprintf(b, ".子程序 %s%s%s\n", m.Name, ret, pub)
	for _, p := range m.Parameters {
		fmt.Fprintf(b, "    .参数 %s, %s\n", p.Name, nm.dataTypeName(p.DataType))
	}
	for _, v := range m.Variables {
		fmt.Fprintf(b, "    .局部变量 %s, %s\n", v.Name, nm.dataTypeName(v.DataType))
	}
	stmts, err := ParseStatementBlock(m.Code.ExpressionData, Decoder(gbk.Decode))
	if err != nil {
		fmt.Fprintf(b, "    ' [反编译失败: %v]\n", err)
	} else {
		writeStmts(b, stmts, 1, nm)
	}
}

func writeStmts(b *strings.Builder, stmts []Stmt, indent int, nm *NameMap) {
	pad := strings.Repeat("    ", indent)
	for _, s := range stmts {
		switch st := s.(type) {
		case *ExprStmt:
			if st.Expr == nil { b.WriteString(pad + "\n"); continue }
			code := exprText(st.Expr, nm, 0)
			if st.Comment != "" { code += "  '" + st.Comment }
			if st.Mask { code = "' " + code }
			b.WriteString(pad + code + "\n")
		case *UnexaminedStmt:
			b.WriteString(pad + st.Code + "\n")
		case *IfStmt:
			b.WriteString(pad + "如果真 (" + exprText(st.Condition, nm, 0) + ")\n")
			writeStmts(b, st.Block, indent+1, nm)
			b.WriteString(pad + "如果真结束\n")
		case *IfElseStmt:
			b.WriteString(pad + "如果 (" + exprText(st.Condition, nm, 0) + ")\n")
			writeStmts(b, st.BlockTrue, indent+1, nm)
			b.WriteString(pad + "否则\n")
			writeStmts(b, st.BlockFalse, indent+1, nm)
			b.WriteString(pad + "如果结束\n")
		case *LoopStmt:
			b.WriteString(pad + loopHeader(st, nm) + "\n")
			writeStmts(b, st.Block, indent+1, nm)
			b.WriteString(pad + loopFooter(st, nm) + "\n")
		case *SwitchStmt:
			b.WriteString(pad + "判断 (" + exprText(st.Cases[0].Condition, nm, 0) + ")\n")
			for _, c := range st.Cases {
				b.WriteString(pad + "    判断某 Case (" + exprText(c.Condition, nm, 0) + ")\n")
				writeStmts(b, c.Block, indent+2, nm)
			}
			b.WriteString(pad + "    默认\n")
			writeStmts(b, st.DefaultBlock, indent+2, nm)
			b.WriteString(pad + "判断结束\n")
		}
	}
}

func loopHeader(l *LoopStmt, nm *NameMap) string {
	switch l.Kind {
	case "while": return "判断循环首 (" + exprText(l.Condition, nm, 0) + ")"
	case "dowhile": return "循环判断首"
	case "counter": return "计次循环首 (" + exprText(l.Count, nm, 0) + ", " + exprText(l.Var, nm, 0) + ")"
	case "for": return "变量循环首 (" + exprText(l.Start, nm, 0) + ", " + exprText(l.End, nm, 0) + ", " + exprText(l.Step, nm, 0) + ", " + exprText(l.Var, nm, 0) + ")"
	}
	return "循环首"
}

func loopFooter(l *LoopStmt, nm *NameMap) string {
	if l.Kind == "dowhile" { return "循环判断尾 (" + exprText(l.Condition, nm, 0) + ")" }
	return "循环尾"
}

// exprText 把表达式转回易语言文本（含运算符中缀）。
func exprText(e Expr, nm *NameMap, parentPrec int) string {
	switch x := e.(type) {
	case nil:
		return ""
	case *NumberLit:
		if x.IsInt { return fmt.Sprintf("%d", x.IntVal) }
		// 整数值的 double 直接显示为整数（避免 1.182192e+06 这类科学计数法）
		if x.Value == float64(int64(x.Value)) {
			return fmt.Sprintf("%d", int64(x.Value))
		}
		return fmt.Sprintf("%g", x.Value)
	case *BoolLit:
		if x.Value { return "真" }
		return "假"
	case *DateTimeLit:
		t := oadateToTime(x.OADate)
		return fmt.Sprintf("[%s]", t.Format("2006年01月02日"))
	case *StringLit:
		return "“" + x.Value + "”"
	case *DefaultValue:
		return ""
	case *ParamListEnd, *ArrayLiteralEnd:
		return ""
	case *Variable:
		return nm.name(x.ID)
	case *MethodPtr:
		return "&" + nm.name(x.MethodID)
	case *ConstantRef:
		return nm.name(x.ConstantID)
	case *EnumConstant:
		return fmt.Sprintf("枚举_%d_%d", x.MemberID, x.StructID)
	case *ArrayLit:
		parts := make([]string, len(x.Items))
		for i, it := range x.Items { parts[i] = exprText(it, nm, 0) }
		return "{" + strings.Join(parts, ", ") + "}"
	case *AccessMember:
		return exprText(x.Target, nm, 10) + "." + nm.name(x.MemberID)
	case *AccessArray:
		return exprText(x.Target, nm, 10) + "[" + exprText(x.Index, nm, 0) + "]"
	case *Call:
		return callText(x, nm, parentPrec)
	}
	return "?"
}

func callText(c *Call, nm *NameMap, parentPrec int) string {
	// 运算符
	if c.Target == nil && c.LibraryID == 0 {
		if op, ok := operatorMap[c.MethodID]; ok {
			needParen := op.prec < parentPrec
			var s string
			switch op.kind {
			case 1: // 一元
				s = op.sym + exprText(firstOr(c.Params, 0), nm, op.prec)
			case 2, 3: // 二元/多目
				parts := make([]string, len(c.Params))
				for i, p := range c.Params { parts[i] = exprText(p, nm, op.prec) }
				s = strings.Join(parts, " "+op.sym+" ")
			}
			if needParen { return "(" + s + ")" }
			return s
		}
	}
	// 普通调用 / 子程序
	var name string
	switch {
	case c.LibraryID == -3: // 外部 DLL 命令（methodID 实为 DLL 声明 ID）
		name = nm.name(c.MethodID)
	case c.LibraryID >= 0: // 支持库命令（命令表需本地 .fne，离线用占位）
		name = nm.libCommandName(c.LibraryID, c.MethodID)
	default: // -2 用户子程序 / -1 空
		name = nm.name(c.MethodID)
	}
	args := make([]string, len(c.Params))
	for i, p := range c.Params { args[i] = exprText(p, nm, 0) }
	call := name + " (" + strings.Join(args, ", ") + ")"
	if c.Target != nil {
		return exprText(c.Target, nm, 10) + "." + call
	}
	return call
}

func firstOr(ps []Expr, i int) Expr {
	if i < len(ps) { return ps[i] }
	return nil
}

func constValue(c *ConstantInfo, nm *NameMap) string {
	switch v := c.Value.(type) {
	case nil: return ""
	case string: return "“" + v + "”"
	case bool: if v { return "真" }; return "假"
	case float64: return fmt.Sprintf("%g", v)
	case []byte: return fmt.Sprintf("<资源: %d 字节>", len(v))
	}
	return ""
}

// OADate: .NET DateTime.ToOADate 的基准是 1899-12-30。
func oadateToTime(oa float64) time.Time {
	base := time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC)
	days := int(oa)
	frac := oa - float64(days)
	nsec := int64(frac * 24 * 60 * 60 * 1e9)
	return base.AddDate(0, 0, days).Add(time.Duration(nsec))
}
