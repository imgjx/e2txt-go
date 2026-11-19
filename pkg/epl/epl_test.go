package epl

import (
	"os"
	"testing"
)

const samplePath = "../../../例子.e"

func loadSample(t *testing.T) *EFile {
	t.Helper()
	data, err := os.ReadFile(samplePath)
	if err != nil {
		t.Skipf("样本文件不可用: %v", err)
	}
	f, err := Load(data)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	return f
}

func TestLoadMagicAndSections(t *testing.T) {
	f := loadSample(t)
	if f.SystemInfo == nil {
		t.Fatal("系统信息段缺失")
	}
	if len(f.Sections) != 10 {
		t.Fatalf("期望 10 个段, 得到 %d", len(f.Sections))
	}
	if f.SystemInfo.ESystemVersion.Major != 5 {
		t.Fatalf("期望易语言 5.x, 得到 %d", f.SystemInfo.ESystemVersion.Major)
	}
}

func TestCodeSection(t *testing.T) {
	f := loadSample(t)
	if f.Code == nil {
		t.Fatal("程序段缺失")
	}
	if len(f.Code.Libraries) != 2 {
		t.Fatalf("期望 2 个支持库, 得到 %d", len(f.Code.Libraries))
	}
	if len(f.Code.Classes) != 1 {
		t.Fatalf("期望 1 个程序集, 得到 %d", len(f.Code.Classes))
	}
	if len(f.Code.Methods) != 2 {
		t.Fatalf("期望 2 个子程序, 得到 %d", len(f.Code.Methods))
	}
	if len(f.Code.DllDeclares) != 2 {
		t.Fatalf("期望 2 个 DLL 命令, 得到 %d", len(f.Code.DllDeclares))
	}
}

func TestNamesDecoded(t *testing.T) {
	f := loadSample(t)
	if f.Code == nil || len(f.Code.Classes) == 0 {
		t.Skip("无程序集")
	}
	if f.Code.Classes[0].Name != "窗口程序集_启动窗口" {
		t.Fatalf("程序集名错误: %q", f.Code.Classes[0].Name)
	}
	found := false
	for _, m := range f.Code.Methods {
		if m.Name == "_按钮1_被单击" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("未找到子程序 _按钮1_被单击")
	}
	if f.Resources != nil && len(f.Resources.Forms) > 0 {
		if f.Resources.Forms[0].Name != "_启动窗口" {
			t.Fatalf("窗口名错误: %q", f.Resources.Forms[0].Name)
		}
	}
}

func TestBytecodeDecompile(t *testing.T) {
	f := loadSample(t)
	if f.Code == nil {
		t.Skip("无程序段")
	}
	decompiled := 0
	for _, m := range f.Code.Methods {
		stmts, err := ParseStatementBlock(m.Code.ExpressionData, decoderForLanguage(f.EncodingLanguage))
		if err != nil {
			t.Fatalf("方法 %s 反编译失败: %v", m.Name, err)
		}
		if len(stmts) > 0 {
			decompiled++
		}
	}
	if decompiled == 0 {
		t.Fatal("没有任何方法成功反编译出语句")
	}
}

func TestGenerateText(t *testing.T) {
	f := loadSample(t)
	text := GenerateText(f)
	for _, kw := range []string{"JCAP_Snap", "窗口程序集_启动窗口", "_按钮1_被单击", "子程序1", "判断循环首"} {
		if !contains(text, kw) {
			t.Fatalf("生成源码缺少关键内容: %s", kw)
		}
	}
}

func TestSaveRoundTrip(t *testing.T) {
	f := loadSample(t)
	if err := VerifyRoundTrip(f); err != nil {
		t.Fatalf("无损往返校验失败: %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}()
}
