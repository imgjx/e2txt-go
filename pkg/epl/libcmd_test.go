package epl

import "testing"

func TestLibCommandNames(t *testing.T) {
	// 表中存的是十进制函数偏移，init 时按 命令号 = 偏移/4 归类。
	// 这里用「命令号」做键验证。
	checks := map[int32]string{
		415: "延时",   // 偏移 0x67C=1660 → /4=415，样本 #415(10)
		192: "信息框",  // 偏移 0x300=768 → /4=192
		90:  "到文本",  // 偏移 0x168=360 → /4=90
		154: "读入文件", // 偏移 0x268=616 → /4=154
		360: "取索引名", // 偏移 0x5A0=1440 → /4=360
	}
	for id, want := range checks {
		if got := krnlnByID[id]; got != want {
			t.Errorf("krnln 命令 %d: 期望 %q, 得到 %q", id, want, got)
		}
	}
	// 原始偏移值本身不应作为命令号命中
	if _, ok := krnlnByID[1660]; ok {
		t.Error("偏移值 1660 不应作为命令号存在于表中")
	}
	if got := libCmdTables["EThread"][0]; got != "启动线程" {
		t.Errorf("多线程命令 0: 期望 启动线程, 得到 %q", got)
	}
}
