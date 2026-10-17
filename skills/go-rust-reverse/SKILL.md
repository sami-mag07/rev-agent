---
name: go-rust-reverse
description: Use for reverse engineering stripped Go and Rust binaries including runtime recognition, pclntab/module data recovery, panic strings, and idiomatic decompilation recovery.
---

# Go / Rust Binary Reverse Engineering

## ACTION REQUIRED（读完后立刻执行）

1. `NOW`: 仅在本地、已授权的 Sandbox 上工作；可疑样本视为 untrusted
2. `NOW`: 确认样本为 Go/Rust 编译产物（`file`/字符串/运行时特征）
3. `NEXT`: 用 `which` 校验工具；**GoReSym 已安装** `~/.local/bin/GoReSym`（v3.4.1，darwin x86_64 走 Rosetta）；redress 本 setup 未安装；两者皆缺则用 `strings` / r2 / 手工 pclntab 解析兜底
4. `ACT`: 运行时识别 → 符号/元数据恢复 → 业务逻辑

## 适用场景

- 剥离符号的 Go 恶意软件/工具
- Rust 发行二进制、panic 字符串驱动分析
- 与通用 ida/ghidra 互补的语言专用方法

## 命名铁律（防幻觉）

- 任何来自反编译器 / 插件（GoReSym 等）给出的函数名，只有在有证据时才作为结论：pclntab 条目、残留符号、调用方上下文、或字符串 xref。
- 无上述证据的名字一律标为「推测」，不得当成事实写进结论或报告。
- 记录每个名字的证据来源（名字 ← 来自哪条证据），无来源即视为未确认。

## 工作流

### Go

```text
□ 识别 go.buildid、runtime 符号残留、pclntab
□ 恢复函数名：首选 `~/.local/bin/GoReSym`（已安装 v3.4.1；`GoReSym <bin>` 输出 JSON，`-p` 路径 `-t` 类型 `-human` 平铺）；redress 未安装；缺则靠 pclntab 自解析 + `strings` + r2 的 Go 分析兜底（恢复出的名字按「命名铁律」标注证据）
□ 注意 interface、slice、string 结构在反编译中的形态
□ 网络/加密库路径：crypto/* net/http
```

### Rust

```text
□ 先判断 Debug 还是 Release：
□   Debug：保留较多符号与路径信息，相对好读，可直接按符号名定位
□   Release（**难**）：范型/trait 单态化导致代码膨胀、符号极少、内联激进，几乎无现成名字；以字符串 xref + panic 信息为主要锚点
□ 通用：panic 字符串、rust_begin_unwind、crate 路径暗示
□ 范型实例化导致的代码膨胀；先定位字符串 xref
□ 异步/tokio 状态机需结合交叉引用
```

### 动态

```text
□ 动态主力 lldb（本 setup 自带）；Frida 本 setup 未安装，用前 `which frida`，缺则仅用 lldb；注意 Go 栈与调度
□ 优先日志与配置字符串驱动断点
```

## 工具链

| 工具 | 用途 | 安装 / 可用性 |
|------|------|------|
| GoReSym | Go 元数据 / 函数名 | **已安装** `~/.local/bin/GoReSym`（v3.4.1，darwin x86_64 走 Rosetta；`-h`/`-about` 已验证 2026-10-09）；非 Go 文件优雅报错 `no valid pclntab found` |
| redress | Go 符号还原 | **本 setup 未安装**；手动安装，缺则同上兜底 |
| IDA/Ghidra + Go/Rust 插件 | 反编译 | **本 setup 均未安装**（IDA 商业；Ghidra 见 `../ghidra-reverse/`） |
| radare2 (r2) | 反汇编 / 快速字符串 | 本 setup 自带（`~/.local/bin`） |
| strings / nm / file | 分诊 | 系统自带（rabin2 随 r2 提供） |

## 参考

- `references/go-rust-notes.md`
- `../reverse-engineering/go-reverse.md`、`../reverse-engineering/languages-compiled.md`（Go/Rust 段）、`../ghidra-reverse/`
- （IDA 本 setup 未安装；Ghidra 亦未安装，见 `../ghidra-reverse/` 的安装说明）

## 相关模块（本 setup）

- 恶意样本流程与 Cloud/Isolation-Gates → `malware-analysis/`
- 通用 RE → `reverse-engineering/`
- Mach-O / macOS 专项 → `macos-reverse/`

## 任务完成自检

- [ ] 是否恢复关键函数名或等价映射？
- [ ] 是否标注语言运行时证据？
- [ ] Checklist？