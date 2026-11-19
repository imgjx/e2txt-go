// e2txt-go：易语言 .e 源码逆向工具（Go 实现）。
//
//   - 精确解析 .e 文件容器、全部数据段、结构化模型
//   - 反编译方法体字节码为表达式/语句 AST
//   - 还原易语言文本源码
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"e2txt-go/pkg/epl"
)

const version = "2.0.0-go"

func main() {
	mode := flag.String("mode", "info", "运行模式: info | view | source | json | build")
	src := flag.String("src", "", "源 .e / .ec 文件")
	dst := flag.String("dst", "", "输出文件（source/json/build 模式）")
	showVer := flag.Bool("version", false, "显示版本")
	flag.Parse()

	if *showVer {
		fmt.Printf("e2txt-go v%s\n易语言 .e 源码与文本互转工具\n", version)
		return
	}
	if *src == "" {
		usage()
		os.Exit(1)
	}

	data, err := os.ReadFile(*src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: 读取文件失败: %v\n", err)
		os.Exit(2)
	}
	f, err := epl.Load(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: 解析失败: %v\n", err)
		os.Exit(3)
	}

	switch *mode {
	case "info":
		printInfo(f, len(data), *src)
	case "view":
		printView(f)
	case "source":
		text := epl.GenerateText(f)
		out := *dst
		if out == "" {
			out = stringsTrimExt(*src) + ".e.txt"
		}
		if err := os.WriteFile(out, []byte(text), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: 写入失败: %v\n", err)
			os.Exit(4)
		}
		fmt.Printf("源码已还原: %s (%d 字节)\n", out, len(text))
	case "json":
		b, err := epl.DumpJSON(f, true)
		if err != nil { fmt.Fprintf(os.Stderr, "ERROR: %v\n", err); os.Exit(5) }
		out := *dst
		if out != "" {
			if err := os.WriteFile(out, b, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: 写入失败: %v\n", err)
				os.Exit(4)
			}
			fmt.Printf("结构已导出: %s\n", out)
		} else {
			fmt.Println(string(b))
		}
	case "build":
		// 反向生成：把结构化模型重新写回 .e 二进制。
		out, err := epl.Save(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: 生成 .e 失败: %v\n", err)
			os.Exit(6)
		}
		dstPath := *dst
		if dstPath == "" {
			dstPath = stringsTrimExt(*src) + ".rebuilt.e"
		}
		if err := os.WriteFile(dstPath, out, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: 写入失败: %v\n", err)
			os.Exit(4)
		}
		if err := epl.VerifyRoundTrip(f); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: 往返校验未通过: %v\n", err)
		} else {
			fmt.Printf("往返校验通过（字节级无损）\n")
		}
		fmt.Printf("已生成 .e: %s (%d 字节)\n", dstPath, len(out))
	default:
		fmt.Fprintf(os.Stderr, "ERROR: 未知模式 %q（可选 info|view|source|json|build）\n", *mode)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("用法: e2txt-go -mode <info|view|source|json|build> -src <文件.e> [-dst <输出文件>]")
	fmt.Println("  info   - 工程统计")
	fmt.Println("  view   - 结构化查看（程序集/子程序/DLL/支持库）")
	fmt.Println("  source - 反编译为易语言文本源码")
	fmt.Println("  json   - 导出完整解析结构为 JSON")
	fmt.Println("  build  - 反向生成：把模型重新写回 .e（字节级无损）")
}

func printInfo(f *epl.EFile, size int, path string) {
	fmt.Printf("文件: %s\n", filepath.Base(path))
	fmt.Printf("大小: %d 字节\n", size)
	if f.SystemInfo != nil {
		fmt.Printf("易语言版本: %d.%d  格式版本: %d.%d  语言码: %d\n",
			f.SystemInfo.ESystemVersion.Major, f.SystemInfo.ESystemVersion.Minor,
			f.SystemInfo.EProjectFormatVer.Major, f.SystemInfo.EProjectFormatVer.Minor,
			f.SystemInfo.Language)
	}
	fmt.Printf("数据段: %d\n", len(f.Sections))
	if f.Code != nil {
		fmt.Printf("支持库: %d\n", len(f.Code.Libraries))
		fmt.Printf("程序集: %d\n", len(f.Code.Classes))
		fmt.Printf("子程序: %d\n", len(f.Code.Methods))
		fmt.Printf("全局变量: %d\n", len(f.Code.GlobalVars))
		fmt.Printf("数据类型: %d\n", len(f.Code.Structs))
		fmt.Printf("DLL命令: %d\n", len(f.Code.DllDeclares))
	}
	if f.Resources != nil {
		fmt.Printf("常量: %d\n", len(f.Resources.Constants))
		fmt.Printf("窗口: %d\n", len(f.Resources.Forms))
	}
}

func printView(f *epl.EFile) {
	fmt.Println("===== 支持库 =====")
	if f.Code != nil {
		for _, l := range f.Code.Libraries {
			fmt.Printf("  %s  {%s}  v%d.%d\n", l.Name, l.GuidString, l.VersionMajor, l.VersionMinor)
		}
		fmt.Println("===== 程序集 =====")
		for _, c := range f.Code.Classes {
			fmt.Printf("  %s (关联窗口ID=%d)\n", c.Name, c.Form)
		}
		fmt.Println("===== 子程序 =====")
		for _, m := range f.Code.Methods {
			pub := ""
			if m.IsPublic() { pub = " [公开]" }
			fmt.Printf("  .子程序 %s%s  (参数%d, 局部变量%d, 字节码%d)\n",
				m.Name, pub, len(m.Parameters), len(m.Variables), len(m.Code.ExpressionData))
		}
		fmt.Println("===== DLL命令 =====")
		for _, d := range f.Code.DllDeclares {
			fmt.Printf("  %s -> %s!%s\n", d.Name, d.LibraryName, d.EntryPoint)
		}
	}
	if f.Resources != nil {
		fmt.Println("===== 常量 =====")
		for _, c := range f.Resources.Constants {
			fmt.Printf("  %s = %v\n", c.Name, c.Value)
		}
		fmt.Println("===== 窗口 =====")
		for _, w := range f.Resources.Forms {
			fmt.Printf("  %s (组件%d)\n", w.Name, len(w.Elements))
		}
	}
}

func stringsTrimExt(s string) string {
	if ext := filepath.Ext(s); ext != "" { return s[:len(s)-len(ext)] }
	return s
}
