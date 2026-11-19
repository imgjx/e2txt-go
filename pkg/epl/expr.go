package epl

import "fmt"

// 本文件实现方法体字节码的表达式反编译，严格对应 CodeDataParser.ParseExpression。

// Expr 是所有表达式节点的接口。
type Expr interface{ isExpr() }

type (
	ParamListEnd    struct{}
	ArrayLiteralEnd struct{}
	DefaultValue    struct{}
	NumberLit       struct{ Value float64; IsInt bool; IntVal int32 }
	BoolLit         struct{ Value bool }
	DateTimeLit     struct{ OADate float64 }
	StringLit       struct{ Value string }
	ConstantRef     struct{ LibraryID, ConstantID int32 } // LibraryID=-2 表示用户常量
	EnumConstant    struct{ StructID, LibraryID, MemberID int32 }
	MethodPtr       struct{ MethodID int32 }
	ArrayLit        struct{ Items []Expr }
	Variable        struct{ ID int32 }
	AccessMember    struct{ Target Expr; LibraryID, StructID, MemberID int32; IsLib bool }
	AccessArray     struct{ Target, Index Expr }
	Call            struct {
		LibraryID, MethodID int32
		Target              Expr
		Params              []Expr
		Unexamined          string
		Comment             string
		Mask                bool
		InvokeSpecial       bool
	}
)

func (*ParamListEnd) isExpr()    {}
func (*ArrayLiteralEnd) isExpr() {}
func (*DefaultValue) isExpr()    {}
func (*NumberLit) isExpr()       {}
func (*BoolLit) isExpr()         {}
func (*DateTimeLit) isExpr()     {}
func (*StringLit) isExpr()       {}
func (*ConstantRef) isExpr()     {}
func (*EnumConstant) isExpr()    {}
func (*MethodPtr) isExpr()       {}
func (*ArrayLit) isExpr()        {}
func (*Variable) isExpr()        {}
func (*AccessMember) isExpr()    {}
func (*AccessArray) isExpr()     {}
func (*Call) isExpr()            {}

const idNaV int32 = 0x0500FFFE

// parseExpression 对应 CodeDataParser.ParseExpression(reader, encoding, parseMember=true)。
func parseExpression(r *Reader, dec Decoder, parseMember bool) (Expr, error) {
	var result Expr
	for {
		t := r.ReadByte()
		switch t {
		case 0x01:
			return &ParamListEnd{}, nil
		case 0x16:
			result = &DefaultValue{}
		case 0x17:
			result = &NumberLit{Value: r.ReadDouble()}
		case 0x18:
			result = &BoolLit{Value: r.ReadInt16() != 0}
		case 0x19:
			result = &DateTimeLit{OADate: r.ReadDouble()}
		case 0x1A:
			result = &StringLit{Value: r.ReadBStr(dec)}
		case 0x1B:
			result = &ConstantRef{LibraryID: -2, ConstantID: r.ReadInt32()}
		case 0x1C:
			lib := int32(r.ReadInt16()) - 1
			cid := int32(r.ReadInt16()) - 1
			result = &ConstantRef{LibraryID: lib, ConstantID: cid}
		case 0x1D:
			continue // 引用标记，跳过（下一字节通常是 0x38）
		case 0x1E:
			result = &MethodPtr{MethodID: r.ReadInt32()}
		case 0x1F: // 数组字面量
			arr := &ArrayLit{}
			for {
				e, err := parseExpression(r, dec, true)
				if err != nil { return nil, err }
				if _, ok := e.(*ArrayLiteralEnd); ok { break }
				arr.Items = append(arr.Items, e)
			}
			result = arr
		case 0x20:
			return &ArrayLiteralEnd{}, nil
		case 0x21: // 调用表达式（无前置类型字节场景）
			e, _, _, _, err := parseCallWithoutType(r, dec)
			if err != nil { return nil, err }
			result = e
		case 0x23: // 枚举常量
			sid := int32(r.ReadInt16()) - 1
			lib := int32(r.ReadInt16()) - 1
			mid := r.ReadInt32() - 1
			result = &EnumConstant{StructID: sid, LibraryID: lib, MemberID: mid}
		case 0x37:
			continue
		case 0x38: // ThisCall 或变量
			v := r.ReadInt32()
			if v == idNaV {
				r.ReadByte() // 0x3A
				return parseExpression(r, dec, true)
			}
			result = &Variable{ID: v}
			parseMember = true
		case 0x3B:
			iv := r.ReadInt32()
			result = &NumberLit{Value: float64(iv), IsInt: true, IntVal: iv}
		default:
			return nil, fmt.Errorf("未知表达式类型字节 0x%02X (pos=%d)", t, r.Pos-1)
		}
		break
	}

	// 成员访问链
	if parseMember && isMemberChainRoot(result) {
		for r.Pos < len(r.Data) {
			b := r.ReadByte()
			switch b {
			case 0x39:
				memberID := r.ReadInt32()
				structID := r.ReadInt32()
				if IsLibDataType(structID) {
					lib := int32(uint16(structID>>16)) - 1
					typ := int32(uint16(structID)) - 1
					result = &AccessMember{Target: result, LibraryID: lib, StructID: typ, MemberID: memberID - 1, IsLib: true}
				} else {
					result = &AccessMember{Target: result, StructID: structID, MemberID: memberID}
				}
			case 0x3A:
				idx, err := parseExpression(r, dec, false)
				if err != nil { return nil, err }
				result = &AccessArray{Target: result, Index: idx}
			case 0x37:
				goto finish
			default:
				_ = r.Seek(r.Pos - 1) // 回退
				goto finish
			}
		}
	}
finish:
	return result, nil
}

func isMemberChainRoot(e Expr) bool {
	switch e.(type) {
	case *Variable, *Call, *AccessMember, *AccessArray:
		return true
	}
	return false
}

// parseCallWithoutType 对应 CodeDataParser.ParseCallExpressionWithoutType。
// 返回：表达式、未审查代码、注释、是否屏蔽、错误。
func parseCallWithoutType(r *Reader, dec Decoder) (*Call, string, string, bool, error) {
	methodID := r.ReadInt32()
	libraryID := r.ReadInt16()
	flag := r.ReadInt16()
	unexamined := r.ReadBStr(dec)
	comment := r.ReadBStr(dec)
	mask := flag&0x20 != 0
	invoke := flag&0x10 != 0

	exp := &Call{
		LibraryID: int32(libraryID), MethodID: methodID,
		Unexamined: unexamined, Comment: comment,
		Mask: mask, InvokeSpecial: invoke,
	}
	if r.Pos < len(r.Data) {
		b := r.ReadByte()
		switch b {
		case 0x36:
			params, err := parseParamList(r, dec)
			if err != nil { return nil, "", "", false, err }
			exp.Params = params
		case 0x38:
			_ = r.Seek(r.Pos - 1)
			target, err := parseExpression(r, dec, true)
			if err != nil { return nil, "", "", false, err }
			exp.Target = target
			params, err := parseParamList(r, dec)
			if err != nil { return nil, "", "", false, err }
			exp.Params = params
		default:
			return nil, "", "", false, fmt.Errorf("调用头后未知字节 0x%02X (pos=%d)", b, r.Pos-1)
		}
	}
	return exp, unexamined, comment, mask, nil
}

// parseParamList 对应 CodeDataParser.ParseParamList（以 0x01 终止）。
func parseParamList(r *Reader, dec Decoder) ([]Expr, error) {
	var params []Expr
	for {
		e, err := parseExpression(r, dec, true)
		if err != nil { return nil, err }
		if _, ok := e.(*ParamListEnd); ok { break }
		params = append(params, e)
	}
	return params, nil
}

// ReadInt32At 读取 r.Data[pos:pos+4]（不移动指针），用于 0x3B 紧凑整数的取值。
func (r *Reader) ReadInt32At(pos int) int32 {
	if pos < 0 || pos+4 > len(r.Data) { return 0 }
	return int32(uint32(r.Data[pos]) | uint32(r.Data[pos+1])<<8 | uint32(r.Data[pos+2])<<16 | uint32(r.Data[pos+3])<<24)
}
