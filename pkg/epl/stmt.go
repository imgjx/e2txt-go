package epl

import "fmt"

// 本文件实现语句块反编译，严格对应 CodeDataParser.ParseStatementBlock。

// Stmt 是所有语句节点的接口。
type Stmt interface{ isStmt() }

type (
	ExprStmt struct {
		Expr    Expr   // nil 表示空调用占位
		Comment string
		Mask    bool
	}
	UnexaminedStmt struct {
		Code string
		Mask bool
	}
	IfStmt struct {
		Condition Expr
		Block     []Stmt
		Comment   string
	}
	IfElseStmt struct {
		Condition   Expr
		BlockTrue   []Stmt
		BlockFalse  []Stmt
		Comment     string
	}
	LoopStmt struct {
		Kind           string // while / dowhile / counter / for
		Condition      Expr
		Count, Start, End, Step, Var Expr
		Block          []Stmt
		Comment        string
		CommentOnEnd   string
	}
	CaseInfo struct {
		Condition Expr
		Block     []Stmt
	}
	SwitchStmt struct {
		Cases        []*CaseInfo
		DefaultBlock []Stmt
	}
)

func (*ExprStmt) isStmt()       {}
func (*UnexaminedStmt) isStmt() {}
func (*IfStmt) isStmt()         {}
func (*IfElseStmt) isStmt()     {}
func (*LoopStmt) isStmt()       {}
func (*SwitchStmt) isStmt()     {}

// knownTypeIDs 对应 CodeDataParser.KnownTypeId（块结束标记 + 语句起始标记）。
var knownTypeIDs = map[byte]bool{
	0x50: true, 0x51: true, 0x52: true, 0x53: true, 0x54: true, 0x55: true,
	0x6A: true, 0x6B: true, 0x6C: true, 0x6D: true, 0x6E: true, 0x6F: true,
	0x70: true, 0x71: true,
}

// ParseStatementBlock 是反编译入口，对应 CodeDataParser.ParseStatementBlock(byte[], encoding)。
func ParseStatementBlock(data []byte, dec Decoder) ([]Stmt, error) {
	r := NewReader(data)
	return parseStatementBlock(r, dec)
}

// parseStatementBlock 对应私有重载 ParseStatementBlock(reader, ..., bool isNotTop)。
func parseStatementBlock(r *Reader, dec Decoder) ([]Stmt, error) {
	var block []Stmt
	for {
		// 步骤1：扫描到下一个已知语句类型字节
		var t byte
		found := false
		for r.Pos < len(r.Data) {
			b := r.ReadByte()
			if knownTypeIDs[b] {
				t = b
				found = true
				break
			}
		}
		if !found {
			return block, nil // 到达流末尾
		}
		startPos := r.Pos - 1

		// 步骤2：块结束标记（回退，不消费）
		switch t {
		case 0x50, 0x51, 0x52, 0x53, 0x54, 0x6F, 0x71:
			_ = r.Seek(startPos)
			return block, nil
		case 0x55:
			continue // 循环体结束标识，跳过
		case 0x6D: // Switch 特例
			sw, err := parseSwitch(r, dec)
			if err != nil { return nil, err }
			block = append(block, sw)
			continue
		}

		// 步骤3：解析调用头
		exp, unexamined, comment, mask, err := parseCallWithoutType(r, dec)
		if err != nil { return nil, err }

		// 步骤4：按类型构造语句
		switch t {
		case 0x6A: // 常规 Call
			if unexamined != "" {
				block = append(block, &UnexaminedStmt{Code: unexamined, Mask: mask})
			} else if exp.LibraryID == -1 {
				block = append(block, &ExprStmt{Expr: nil, Comment: comment})
			} else {
				block = append(block, &ExprStmt{Expr: exp, Comment: comment, Mask: mask})
			}
		case 0x6C: // 如果真 (If)
			inner, err := parseStatementBlock(r, dec)
			if err != nil { return nil, err }
			if r.ReadByte() != 0x52 { return nil, fmt.Errorf("If 缺少结束标记 0x52") }
			r.ReadByte() // 0x73
			cond := firstParam(exp)
			block = append(block, &IfStmt{Condition: cond, Block: inner, Comment: comment})
		case 0x6B: // 如果 (IfElse)
			trueBlock, err := parseStatementBlock(r, dec)
			if err != nil { return nil, err }
			if r.ReadByte() != 0x50 { return nil, fmt.Errorf("IfElse 缺少否则标记 0x50") }
			falseBlock, err := parseStatementBlock(r, dec)
			if err != nil { return nil, err }
			if r.ReadByte() != 0x51 { return nil, fmt.Errorf("IfElse 缺少结束标记 0x51") }
			r.ReadByte() // 0x72
			block = append(block, &IfElseStmt{Condition: firstParam(exp), BlockTrue: trueBlock, BlockFalse: falseBlock, Comment: comment})
		case 0x70: // 循环
			loopBlock, err := parseStatementBlock(r, dec)
			if err != nil { return nil, err }
			// 0x55（循环体结束标识）已由 parseStatementBlock 的 continue 跳过，
			// 返回时指针停在 0x71，此处直接读取循环结束标记。
			if r.ReadByte() != 0x71 { return nil, fmt.Errorf("循环缺少结束标记 0x71") }
			endExp, _, endComment, _, err := parseCallWithoutType(r, dec)
			if err != nil { return nil, err }
			if exp.LibraryID != 0 { return nil, fmt.Errorf("循环 LibraryId 非0") }
			ls := &LoopStmt{Block: loopBlock, Comment: comment, CommentOnEnd: endComment}
			switch exp.MethodID {
			case 3: // 判断循环 (While)
				ls.Kind, ls.Condition = "while", firstParam(exp)
			case 5: // 循环判断 (DoWhile)
				ls.Kind, ls.Condition = "dowhile", firstParam(endExp)
			case 7: // 计次循环
				ls.Kind = "counter"
				if len(exp.Params) > 0 { ls.Count = exp.Params[0] }
				if len(exp.Params) > 1 { ls.Var = exp.Params[1] }
			case 9: // 变量循环
				ls.Kind = "for"
				if len(exp.Params) > 0 { ls.Start = exp.Params[0] }
				if len(exp.Params) > 1 { ls.End = exp.Params[1] }
				if len(exp.Params) > 2 { ls.Step = exp.Params[2] }
				if len(exp.Params) > 3 { ls.Var = exp.Params[3] }
			default:
				return nil, fmt.Errorf("未知循环 MethodId=%d", exp.MethodID)
			}
			block = append(block, ls)
		default:
			return nil, fmt.Errorf("未知语句类型 0x%02X", t)
		}
	}
}

// parseSwitch 对应 0x6D 分支。
func parseSwitch(r *Reader, dec Decoder) (*SwitchStmt, error) {
	if r.ReadByte() != 0x6E { return nil, fmt.Errorf("Switch 首字节非 0x6E") }
	s := &SwitchStmt{}
	for {
		caseExp, _, _, _, err := parseCallWithoutType(r, dec)
		if err != nil { return nil, err }
		caseBlock, err := parseStatementBlock(r, dec)
		if err != nil { return nil, err }
		if r.ReadByte() != 0x53 { return nil, fmt.Errorf("Switch Case 缺少 0x53") }
		s.Cases = append(s.Cases, &CaseInfo{Condition: firstParam(caseExp), Block: caseBlock})
		t := r.ReadByte()
		if t != 0x6E {
			if t != 0x6F { return nil, fmt.Errorf("Switch 期望 0x6E/0x6F, 得 0x%02X", t) }
			break
		}
	}
	def, err := parseStatementBlock(r, dec)
	if err != nil { return nil, err }
	s.DefaultBlock = def
	if r.ReadByte() != 0x54 { return nil, fmt.Errorf("Switch 缺少结束标记 0x54") }
	r.ReadByte() // 0x74
	return s, nil
}

func firstParam(e *Call) Expr {
	if e != nil && len(e.Params) > 0 { return e.Params[0] }
	return nil
}
