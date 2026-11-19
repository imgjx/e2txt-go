package epl

import (
	"bytes"
	"testing"
)

// TestAssemblerRoundTrip 验证：反编译字节码 → 重新编码，ExpressionData 应逐字节一致。
// 这是"文本/结构 → .e"反向生成正确性的核心保证。
func TestAssemblerRoundTrip(t *testing.T) {
	f := loadSample(t)
	if f.Code == nil {
		t.Skip("无程序段")
	}
	dec := decoderForLanguage(f.EncodingLanguage)
	for _, m := range f.Code.Methods {
		stmts, err := ParseStatementBlock(m.Code.ExpressionData, dec)
		if err != nil {
			t.Fatalf("方法 %s 反编译失败: %v", m.Name, err)
		}
		code, err := AssembleCode(stmts)
		if err != nil {
			t.Fatalf("方法 %s 重新编码失败: %v", m.Name, err)
		}
		if !bytes.Equal(m.Code.ExpressionData, code.ExpressionData) {
			t.Errorf("方法 %s 的 ExpressionData 不一致:\n原始(%d): % X\n重编码(%d): % X",
				m.Name, len(m.Code.ExpressionData), m.Code.ExpressionData,
				len(code.ExpressionData), code.ExpressionData)
		}
		t.Logf("方法 %s: 原始=%d 字节, 重编码=%d 字节, 语句数=%d",
			m.Name, len(m.Code.ExpressionData), len(code.ExpressionData), len(stmts))

		// 逐一比对 6 段
		pairs := [][2][]byte{
			{m.Code.LineOffset, code.LineOffset},
			{m.Code.BlockOffset, code.BlockOffset},
			{m.Code.MethodRef, code.MethodRef},
			{m.Code.VariableRef, code.VariableRef},
			{m.Code.ConstantRef, code.ConstantRef},
		}
		names := []string{"LineOffset", "BlockOffset", "MethodRef", "VariableRef", "ConstantRef"}
		for i, p := range pairs {
			if !bytes.Equal(p[0], p[1]) {
				t.Logf("  %s 不一致: 原始(%d)=% X / 重编码(%d)=% X",
					names[i], len(p[0]), p[0], len(p[1]), p[1])
			}
		}
	}
}

