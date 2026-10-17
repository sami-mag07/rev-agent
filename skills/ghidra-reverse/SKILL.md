---
name: ghidra-reverse
description: Use for free/open reverse engineering with Ghidra (headless or GUI), including decompile, cross-refs, and optional Ghidra MCP workflows when IDA is unavailable.
---

# Ghidra Reverse Engineering

## ACTION REQUIRED（读完后立刻执行）

1. `NOW`: 仅在本地、已授权的 Sandbox 上工作；可疑样本视为 untrusted
2. `NOW`: 确认需要 **Ghidra**（本 setup 无 IDA / 偏好开源 / 批量 headless）
3. `NEXT`: 用 `which` / `--version` 校验本地工具；**本 setup 未安装 Ghidra、analyzeHeadless 与 JDK**，需先装（macOS: 先装 Homebrew → `brew install --cask ghidra`；Ghidra 以 JDK 17/21 为必备前提，缺 JDK 则先装 JDK 17 或 21）。**JDK 校验：`which java` 不足以证明有 JDK——`/usr/bin/java` 只是 Apple-Stub，`which` 总会命中它；真正的 JDK 只认 `java -version`（无 JDK 时会报 „Unable to locate a Java Runtime"）。**
4. `ACT`: 导入样本 → 自动分析 → 导出关键函数反编译

## 适用场景

- 无 IDA 许可证时的主逆向入口
- 批量 headless 分析 / CI 中反编译
- Ghidra 脚本（Java/Python Jython/PyGhidra）自动化
- 补丁差分：ghidriff（Ghidra 自带工作流；binary-diff / patch-diff-exploit 作为独立 skill 在本 setup 未安装）

## 工具分工（本 setup）

| 需求 | 优先 |
|------|------|
| 反编译 / 深挖 | **本 skill**（Ghidra；IDA 作为独立 skill 未安装） |
| 开源 / 批量 / 教学 | **本 skill** |
| 仅 CLI 快速侦察 | `radare2/` |

## 工作流

### 1. 项目与自动分析

```text
□ 新建 Project → Import 文件 → Analyze（默认分析器）
□ 记录语言/编译器识别结果与基址
□ 标记入口、导出表、字符串 xref
```

### 2. 关键函数

```text
□ 从字符串 / 导入 API 反查
□ Decompile 窗口还原算法
□ 重命名函数/变量；写 Plate comment
□ 需要动态时交接 lldb（本 setup 自带）；Frida 本 setup 未安装，用前先 `which frida` 校验（reverse-engineering 动态章）
```

### 3. Headless（批量）

```bash
# 本 setup 未安装 Ghidra / analyzeHeadless：先按工具链安装（含 JDK 17/21）。
# 安装后：Cask 只链接 `ghidraRun`，不链接 analyzeHeadless。analyzeHeadless 位于 App-Bundle 的 support/ 目录
# （形如 .../ghidra_*/support/analyzeHeadless），`which analyzeHeadless` 多半找不到 → 从 `ghidraRun` 的真实安装目录回溯到同级 support/ 定位，别指望它在 bin/ 或 PATH 里。
# 注意：Cask 不提供 `brew --prefix ghidra`（那是公式用法），不要用它定位路径。
analyzeHeadless /path/to/project Proj -import sample.bin -postScript ExportDecomp.py
```

### 4. MCP（若已配置）

```text
□ 确认 ghidra MCP 端口（常见 8765，以本地实际配置为准）
□ 用 MCP 工具拉反编译 / xrefs，禁止猜端口
```

## 工具链

| 工具 | 用途 | 安装 |
|------|------|------|
| Ghidra | 反编译主工具 | **本 setup 未安装**；macOS: 先装 Homebrew → `brew install --cask ghidra`（必须带 `--cask`，无 `--cask` 的直装公式不可用） |
| JDK 17/21 | Ghidra 运行前提 | **本 setup 未安装**；Ghidra 依赖 JDK，缺则无法启动，先装 JDK 17 或 21 |
| ghidra-mcp | AI 桥 | 手动安装（可选，依赖已装的 Ghidra） |
| ghidriff | 补丁差分 | `pip install ghidriff`（binary-diff/patch-diff-exploit 作为独立 skill 未安装） |

## 参考

- `references/ghidra-cheatsheet.md`
- `../radare2/`（CLI 侦察）、`../macos-reverse/`（Mach-O）、`../malware-analysis/`（样本流程）

## 相关模块（本 setup）

- 动态验证 → lldb（本 setup 自带）；Frida 本 setup 未安装（用前 `which frida`）；GDB 在 arm64-macOS 不可用（见 `reverse-engineering/tools-dynamic.md`、`macos-reverse/`）
- CLI 快速侦察 → `radare2/`
- （利用 pwn-chain、IDA 作为独立 skill 在本 setup 未安装）

## 任务完成自检

- [ ] 是否用 `which` / `--version` 校验了真实 Ghidra 路径？
- [ ] 是否标注函数地址与重命名？
- [ ] 是否有可复现步骤？
- [ ] Checklist / journal？