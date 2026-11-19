package epl

import (
	"fmt"
)

// 本文件实现字节码的重新编码（assembler），是反编译器 expr.go/stmt.go 的逆过程。
// 有了它，结构化模型（经文本/JSON 编辑后）即可重新生成方法体的 6 段 CodeData。

const idNaVInt = int32(0x0500FFFE)

// codeAssembler 汇总一次方法体编码产生的 6 段字节流。
type codeAssembler struct {
	lineOffset   *Writer
	blockOffset  *Writer
	methodRef    *Writer
	variableRef  *Writer
	constantRef  *Writer
	expr         *Writer
}

func newCodeAssembler() *codeAssembler {
	return &codeAssembler{
		lineOffset: NewWriter(), blockOffset: NewWriter(),
		methodRef: NewWriter(), variableRef: NewWriter(),
		constantRef: NewWriter(), expr: NewWriter(),
	}
}

func (a *codeAssembler) offset() int32 { return int32(len(a.expr.Bytes())) }

// writeBStr 对应 WriteBStr(dec, value)：null → int32(0)，否则 int32(len+1)+bytes+0。
func writeBStr(w *Writer, s string) {
	b, _ := gbkEncode(s)
	w.WriteInt32(int32(len(b) + 1))
	w.WriteBytes(b)
	w.WriteByte(0)
}

// blockScope 对应 NewBlock(type)：在 BlockOffset 写 [type, startOffset, endOffset]，
// 结束时回填 endOffset（当前 ExpressionData 偏移）。
type blockScope struct {
	a       *codeAssembler
	typ     byte
	endPos  int
}

func (a *codeAssembler) newBlock(typ byte) *blockScope {
	a.blockOffset.WriteByte(typ)
	a.blockOffset.WriteInt32(a.offset())
	pos := len(a.blockOffset.Bytes())
	a.blockOffset.WriteInt32(0)
	return &blockScope{a: a, endPos: pos}
}

func (b *blockScope) close() {
	end := b.a.offset()
	buf := b.a.blockOffset.buf
	buf[b.endPos] = byte(end)
	buf[b.endPos+1] = byte(end >> 8)
	buf[b.endPos+2] = byte(end >> 16)
	buf[b.endPos+3] = byte(end >> 24)
}

// ---------- 表达式编码 ----------

func (a *codeAssembler) writeExpr(e Expr) error {
	switch x := e.(type) {
	case *NumberLit:
		a.expr.WriteByte(0x17)
		a.expr.WriteUInt64(float64bits(x.Value))
	case *BoolLit:
		a.expr.WriteByte(0x18)
		if x.Value { a.expr.WriteInt16(-1) } else { a.expr.WriteInt16(0) }
	case *DateTimeLit:
		a.expr.WriteByte(0x19)
		a.expr.WriteUInt64(float64bits(x.OADate))
	case *StringLit:
		a.expr.WriteByte(0x1A)
		writeBStr(a.expr, x.Value)
	case *DefaultValue:
		a.expr.WriteByte(0x16)
	case *ConstantRef:
		if x.LibraryID == -2 {
			a.constantRef.WriteInt32(a.offset())
			a.expr.WriteByte(0x1B)
			a.expr.WriteInt32(x.ConstantID)
		} else {
			a.expr.WriteByte(0x1C)
			a.expr.WriteInt16(int16(x.LibraryID + 1))
			a.expr.WriteInt16(int16(x.ConstantID + 1))
		}
	case *EnumConstant:
		a.expr.WriteByte(0x23)
		a.expr.WriteInt16(int16(x.StructID + 1))
		a.expr.WriteInt16(int16(x.LibraryID + 1))
		a.expr.WriteInt32(x.MemberID + 1)
	case *MethodPtr:
		a.methodRef.WriteInt32(a.offset())
		a.expr.WriteByte(0x1E)
		a.expr.WriteInt32(x.MethodID)
	case *ArrayLit:
		a.expr.WriteByte(0x1F)
		for _, it := range x.Items {
			if err := a.writeExpr(it); err != nil { return err }
		}
		a.expr.WriteByte(0x20)
	case *Variable:
		a.writeVarRefMarker()
		a.writeExprIn38(x, false)
		a.expr.WriteByte(0x37)
	case *AccessMember:
		a.writeVarRefMarker()
		a.writeExprIn38(x, false)
		a.expr.WriteByte(0x37)
	case *AccessArray:
		a.writeVarRefMarker()
		a.writeExprIn38(x, false)
		a.expr.WriteByte(0x37)
	case *Call:
		// 表达式上下文的调用：type 0x21，无注释、无屏蔽
		return a.writeCall(x, 0x21, false, "")
	case nil:
		// 空参数：写参数列表结束符
		a.expr.WriteByte(0x01)
	default:
		return fmt.Errorf("无法编码表达式类型 %T", e)
	}
	return nil
}

// writeVarRefMarker 写 0x1D 0x38 并登记变量引用偏移。
func (a *codeAssembler) writeVarRefMarker() {
	a.variableRef.WriteInt32(a.offset())
	a.expr.WriteByte(0x1D)
	a.expr.WriteByte(0x38)
}

// writeIn38Prefix 判断某表达式是否属于 In0x38Expression（写 0x1D/0x38 前缀的类型）。
func isIn38(e Expr) bool {
	switch e.(type) {
	case *Variable, *AccessMember, *AccessArray, *Call:
		return true
	}
	return false
}

// writeExprIn38 对应 In0x38Expression.WriteTo(a, need0x1DAnd0x37)。
func (a *codeAssembler) writeExprIn38(e Expr, needMarker bool) error {
	if needMarker {
		a.writeVarRefMarker()
	}
	switch x := e.(type) {
	case *Variable:
		a.expr.WriteInt32(x.ID)
	case *AccessMember:
		if err := a.writeMemberTarget(x.Target); err != nil { return err }
		a.expr.WriteByte(0x39)
		if x.IsLib {
			a.expr.WriteInt32(x.MemberID + 1)
			packed := int32((uint32(x.StructID+1) & 0xFFFF) | (uint32(x.LibraryID+1) << 16))
			a.expr.WriteInt32(packed)
		} else {
			a.expr.WriteInt32(x.MemberID)
			a.expr.WriteInt32(x.StructID)
		}
	case *AccessArray:
		if err := a.writeMemberTarget(x.Target); err != nil { return err }
		a.expr.WriteByte(0x3A)
		if n, ok := x.Index.(*NumberLit); ok {
			// 数组下标整数用 0x3B 紧凑编码（对应读取端的 0x3B）
			a.expr.WriteByte(0x3B)
			a.expr.WriteInt32(n.IntVal)
		} else if isIn38(x.Index) {
			a.expr.WriteByte(0x38)
			if err := a.writeExprIn38(x.Index, false); err != nil { return err }
			a.expr.WriteByte(0x37)
		} else {
			if err := a.writeExpr(x.Index); err != nil { return err }
		}
	case *Call:
		return a.writeCall(x, 0x21, false, "")
	default:
		return fmt.Errorf("表达式 %T 不是 In0x38 类型", e)
	}
	if needMarker {
		a.expr.WriteByte(0x37)
	}
	return nil
}

// writeMemberTarget 写成员/数组访问的 Target 部分。
func (a *codeAssembler) writeMemberTarget(target Expr) error {
	if isIn38(target) {
		return a.writeExprIn38(target, false)
	}
	a.expr.WriteInt32(idNaVInt)
	a.expr.WriteByte(0x3A)
	return a.writeExpr(target)
}

// writeCall 对应 CallExpression.WriteTo(a, type, mask, comment)。
func (a *codeAssembler) writeCall(c *Call, typ byte, mask bool, comment string) error {
	if c.Target != nil {
		a.variableRef.WriteInt32(a.offset())
	}
	if c.LibraryID == -2 || c.LibraryID == -3 {
		a.methodRef.WriteInt32(a.offset())
	}
	a.expr.WriteByte(typ)
	a.expr.WriteInt32(c.MethodID)
	a.expr.WriteInt16(int16(c.LibraryID))
	flags := int16(0)
	if mask { flags |= 0x20 }
	if c.InvokeSpecial { flags |= 0x10 }
	a.expr.WriteInt16(flags)
	// unexamined 恒为 null
	a.expr.WriteInt32(0)
	if comment == "" {
		a.expr.WriteInt32(0)
	} else {
		writeBStr(a.expr, comment)
	}
	if c.Target == nil {
		a.expr.WriteByte(0x36)
	} else {
		a.expr.WriteByte(0x38)
		if isIn38(c.Target) {
			if err := a.writeExprIn38(c.Target, false); err != nil { return err }
		} else {
			a.expr.WriteInt32(idNaVInt)
			a.expr.WriteByte(0x3A)
			if err := a.writeExpr(c.Target); err != nil { return err }
		}
		a.expr.WriteByte(0x37)
	}
	// 参数列表
	for _, p := range c.Params {
		if err := a.writeExpr(p); err != nil { return err }
	}
	a.expr.WriteByte(0x01)
	return nil
}

// ---------- 语句编码 ----------

func (a *codeAssembler) writeStmtBlock(stmts []Stmt) error {
	for _, s := range stmts {
		if err := a.writeStmt(s); err != nil { return err }
	}
	return nil
}

func (a *codeAssembler) writeStmt(s Stmt) error {
	switch st := s.(type) {
	case *ExprStmt:
		a.lineOffset.WriteInt32(a.offset())
		if st.Expr == nil {
			return a.writeCall(&Call{LibraryID: -1, MethodID: 0}, 0x6A, st.Mask, st.Comment)
		}
		if c, ok := st.Expr.(*Call); ok {
			return a.writeCall(c, 0x6A, st.Mask, st.Comment)
		}
		// 非调用的裸表达式：包装成 ParameterList 调用
		return a.writeCall(&Call{LibraryID: 0, MethodID: 0, Params: []Expr{st.Expr}}, 0x6A, st.Mask, st.Comment)
	case *UnexaminedStmt:
		a.lineOffset.WriteInt32(a.offset())
		a.expr.WriteByte(0x6A)
		a.expr.WriteInt32(0)
		a.expr.WriteInt16(-1)
		if st.Mask { a.expr.WriteInt16(0) } else { a.expr.WriteInt16(0x40) }
		writeBStr(a.expr, st.Code)
		a.expr.WriteInt32(0)
		a.expr.WriteByte(0x36)
		a.expr.WriteByte(0x01)
	case *IfStmt:
		b := a.newBlock(2)
		cond := &Call{LibraryID: 0, MethodID: 1, Params: []Expr{st.Condition}}
		if err := a.writeCall(cond, 0x6C, false, st.Comment); err != nil { return err }
		if err := a.writeStmtBlock(st.Block); err != nil { return err }
		a.expr.WriteByte(0x52)
		b.close()
		a.expr.WriteByte(0x73)
	case *IfElseStmt:
		b := a.newBlock(1)
		cond := &Call{LibraryID: 0, MethodID: 0, Params: []Expr{st.Condition}}
		if err := a.writeCall(cond, 0x6B, false, st.Comment); err != nil { return err }
		if err := a.writeStmtBlock(st.BlockTrue); err != nil { return err }
		a.expr.WriteByte(0x50)
		if err := a.writeStmtBlock(st.BlockFalse); err != nil { return err }
		a.expr.WriteByte(0x51)
		b.close()
		a.expr.WriteByte(0x72)
	case *LoopStmt:
		b := a.newBlock(3)
		mid, endMethod := a.loopHeaderIDs(st)
		head := &Call{LibraryID: 0, MethodID: mid, Params: a.loopParams(st)}
		if err := a.writeCall(head, 0x70, false, st.Comment); err != nil { return err }
		if err := a.writeStmtBlock(st.Block); err != nil { return err }
		a.expr.WriteByte(0x55)
		b.close()
		end := &Call{LibraryID: 0, MethodID: endMethod, Params: a.loopEndParams(st)}
		if err := a.writeCall(end, 0x71, false, st.CommentOnEnd); err != nil { return err }
	case *SwitchStmt:
		b := a.newBlock(4)
		a.expr.WriteByte(0x6D)
		for _, c := range st.Cases {
			caseCall := &Call{LibraryID: 0, MethodID: 2, Params: []Expr{c.Condition}}
			if err := a.writeCall(caseCall, 0x6E, false, ""); err != nil { return err }
			if err := a.writeStmtBlock(c.Block); err != nil { return err }
			a.expr.WriteByte(0x53)
		}
		a.expr.WriteByte(0x6F)
		if err := a.writeStmtBlock(st.DefaultBlock); err != nil { return err }
		a.expr.WriteByte(0x54)
		b.close()
		a.expr.WriteByte(0x74)
	default:
		return fmt.Errorf("无法编码语句类型 %T", s)
	}
	return nil
}

func (a *codeAssembler) loopHeaderIDs(l *LoopStmt) (int32, int32) {
	switch l.Kind {
	case "while": return 3, 4
	case "dowhile": return 5, 6
	case "counter": return 7, 8
	case "for": return 9, 10
	}
	return 3, 4
}

func (a *codeAssembler) loopParams(l *LoopStmt) []Expr {
	switch l.Kind {
	case "while": return []Expr{l.Condition}
	case "dowhile": return []Expr{}
	case "counter": return []Expr{l.Count, l.Var}
	case "for": return []Expr{l.Start, l.End, l.Step, l.Var}
	}
	return []Expr{}
}

func (a *codeAssembler) loopEndParams(l *LoopStmt) []Expr {
	if l.Kind == "dowhile" { return []Expr{l.Condition} }
	return []Expr{}
}

// AssembleCode 把语句块重新编码为完整的 6 段 MethodCodeData。
func AssembleCode(stmts []Stmt) (MethodCodeData, error) {
	a := newCodeAssembler()
	if err := a.writeStmtBlock(stmts); err != nil {
		return MethodCodeData{}, err
	}
	return MethodCodeData{
		LineOffset: a.lineOffset.Bytes(), BlockOffset: a.blockOffset.Bytes(),
		MethodRef: a.methodRef.Bytes(), VariableRef: a.variableRef.Bytes(),
		ConstantRef: a.constantRef.Bytes(), ExpressionData: a.expr.Bytes(),
	}, nil
}
