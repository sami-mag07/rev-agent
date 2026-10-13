---
name: radare2
description: |
  Use this skill whenever the user wants to analyze binaries with radare2/r2 from the command line, including reverse engineering, disassembly, function analysis, strings/import inspection, patching, binary diffing, hex inspection, or r2 scripting. Also use it when the user mentions PE/ELF/Mach-O/DEX/WASM files together with CLI analysis, `rabin2`, `rasm2`, `radiff2`, `r2pipe`, or asks for radare2 command help on Windows/Linux/macOS.
---

# radare2

面向 `radare2` CLI 的二进制分析技能。重点是直接用命令行完成侦察、分析、定位、导出和轻量修改，不依赖 GUI。

## ACTION REQUIRED（读完后立刻执行）

1. `NOW`: 仅在本地、已授权的 Sandbox 上工作；可疑样本视为 untrusted，不在 Host 上执行
2. `NOW`: 确认当前任务是否命中本 skill 的适用范围
3. `NEXT`: 用 `which r2 rabin2` / `r2 -v` 校验本地工具实际路径；缺工具时本地安装（macOS: `brew install radare2`），不要猜路径
4. `ACT`: 进入"工作流"第一步并执行，不要停在确认状态

## 适用范围

当用户有这些意图时应优先使用本 skill：

- 要用 `r2` / `radare2` 分析 `exe`、`dll`、`so`、`elf`、`apk`、`dex`、`wasm` 等文件
- 询问 `rabin2`、`rasm2`、`radiff2`、`rahash2`、`rax2` 怎么用
- 需要命令行反汇编、看函数、看字符串、看导入导出、查交叉引用、做 patch
- 需要写 `radare2` 批处理命令、`-c` 自动化命令、或 `r2pipe` 脚本

如果需要反编译/伪代码（Hex-Rays 风格）：**r2ghidra 已安装**（验证 2026-10-09），在 r2 内直接 `pdg`（当前函数真正的 Ghidra 伪 C，插件 `~/.local/share/radare2/plugins/core_ghidra.dylib`），比内置 `pdc`（r2 自称 experimental/unreliable）可靠得多；更重的工作（完整项目、脚本化）才转 `ghidra-reverse`（IDA 作为独立 skill 未安装）。如果是网页 JS 逆向，优先考虑 `reverse-engineering`。

## 先做环境确认

先不要假设 `r2` 可用。先检查：

```bash
r2 -v
rabin2 -v
```

如果未安装，再检查常见安装位置或提示安装（macOS: `brew install radare2`）。

本地可执行文件（macOS/Linux）：`r2` / `radare2`、`rabin2`、`rasm2`、`radiff2`、`rahash2`、`rax2`、`r2pm`。Windows 版对应 `*.exe`，仅在 Windows 环境相关。

## 内置资源

这个 skill 自带两个资源，优先复用，不要每次临时组织一套重复命令。

### `scripts/recon.sh`

标准侦察脚本（bash），适合先做第一轮概况分析。会输出：

- 基本信息
- 节区
- 导入
- 导出
- 字符串
- 可选的 `r2 -A` 自动分析摘要

调用方式：

```bash
bash "<skill-root>/radare2/scripts/recon.sh" /path/to/sample.bin
```

如果需要附带 `r2` 自动分析：

```bash
bash "<skill-root>/radare2/scripts/recon.sh" /path/to/sample.bin --analyze
```

### `references/cheatsheet.md`

当需要更多命令细节、常见场景模板、或要快速回忆语法时，读取这个速查表，而不是凭记忆硬猜。

## 已知现象

### Windows 下偶发 `.sdb` 缺失告警

某些 PE 文件在 `rabin2` 侦察时，可能出现类似下面的告警：

```text
ERROR: Cannot find ...\share\format\dll\*.sdb
```

如果主体输出仍然正常返回，通常不影响基础侦察结论，先继续分析即可。不要因为这类附带告警就直接判定分析失败。

## 基本原则

### 1. 先侦察，后深挖

不要一上来就全量自动分析。先用轻量命令确认文件类型、架构、入口点、字符串、导入表，再决定是否做 `aaa`、`aaaa` 或定向分析。

### 2. 优先最小足够命令

`radare2` 命令非常多，用户通常只需要最短路径：

- 看文件信息：`rabin2 -I`
- 看字符串：`rabin2 -z`
- 看导入导出：`rabin2 -i` / `rabin2 -E`
- 交互分析：`r2 <file>` 后再执行局部命令

### 3. 修改前保持谨慎

如果用户要 patch 二进制：

- 默认先只读打开：`r2 <file>`
- 只有在明确需要修改时再用写模式：`r2 -w <file>` 或会话中 `oo+`
- 修改前先告知风险，避免无意覆盖原文件

## 常用工作流

## 工作流 1：快速侦察

适合刚拿到一个二进制文件时。

### 硬门禁（MUST — 未满足禁止进入工作流 2 及后续）

对 PE/ELF/Mach-O 等含导入表的二进制，**MUST** 先完成导入表检查并落成 Evidence，再进入函数级分析或动态步骤：

1. 执行 `rabin2 -i <sample>`（或 `recon.sh` 输出中的 imports 段）；DLL/SYS 另 MUST `rabin2 -E` 并记 `E-exports`
2. 将完整/分类后的导入表结果写入 Evidence（建议 id：`E-imports` 或 `E-triage-imports`），至少包含：
   - 复现命令（`repro_command`）
   - 关键导入分类摘要：网络 / 文件 / 加密 / 进程注入 / 注册表 / 其他可疑 API
   - 若导入表为空、解析失败或工具报错：仍 MUST 记录失败现象与原始输出为 Evidence，**不得静默跳过**
   - 导入表「过干净」（仅基础 DLL）：MUST 注明动态加载嫌疑，SHOULD 转入动态抓 API
3. .NET 等无传统 IAT：MUST 走等价锚点（dnSpy/IL/元数据摘要）写入同一 Evidence 语义槽，禁止空过
4. 加壳样本 IAT 修复（仅 Windows-PE）：x86 用 ImportREC（或等价）、x64 用 Scylla（或等价），均为 [Windows/VM]-Tools。修复失败 MUST 记 `E-iat-repair-fail` 后转动态 API 断点；**禁止**在静态 IAT 上无限死磕（见 `reverse-engineering/references/re-agent-workflow.md` §1.2）。arm64 Mach-O 无此路径 → `macos-reverse`（lldb/Frida）
5. 用户明确要求「重做导入表检查 / 重新检查导入表 / 重做 IAT」时：MUST 重做被点名步骤本身（阻塞时先走可行性门闩：说明前提+请确认；强制则标 quality=unreadable），**禁止改换为无关步骤冒充完成**

未记录导入表（或合法等价锚点 / IAT 失败旁路）Evidence 前：MUST NOT 声称「基础侦察完成」，MUST NOT 进入工作流 2+ 的深挖结论。

优先直接运行内置脚本：

```bash
bash "<skill-root>/radare2/scripts/recon.sh" sample.bin
```

如果只需要手动最小命令，则使用：

```bash
rabin2 -I sample.bin
rabin2 -z sample.bin
rabin2 -i sample.bin
rabin2 -E sample.bin
```

关注点：

- 文件格式、位数、架构、平台
- 入口点地址
- 可疑字符串：URL、路径、报错、注册表、命令行参数
- 导入函数：网络、文件、加密、进程注入、注册表操作（**MUST 落 Evidence，见上方硬门禁**）

## 工作流 2：交互式分析函数

```text
r2 sample.bin
```

进入后常用：

```text
aaa          # 常规自动分析
afl          # 列出函数
iz           # 列出字符串
iS           # 列节区
is           # 列符号
s entry0     # 跳到入口点
pdf          # 反汇编当前函数
pdg          # 当前函数的 Ghidra 伪 C（r2ghidra 已装；pdgj=JSON, pdga=并排）
VV           # 进入可视化模式（如果终端适合）
q            # 退出
```

说明：

- 默认优先 `aaa`，不要一开始就用更重的 `aaaa`
- 如果样本很大或分析很慢，可以只分析入口附近，再手动扩展

## 工作流 3：定位 main / 关键逻辑

```text
afl~main
afl~sym.
iz~http
iz~error
axt <addr>
```

思路：

- 先从 `main`、入口点、字符串引用入手
- 用 `axt` 查谁引用了某个字符串或地址
- 找到引用点后再 `s <addr>`、`pdf`

## 工作流 4：十六进制与内存查看

```text
px 64        # 当前地址起 64 字节十六进制
pd 20        # 反汇编 20 条指令
psz          # 读取当前地址字符串
pxa          # 更友好的十六进制视图
```

## 工作流 5：二进制 patch

仅当用户明确要求修改文件时使用。

### Patch 验证闸（MUST — 每次 patch 都走完）

1. **patch 前先备份**（MUST，不是「最好」）：`cp sample.bin sample.bin.orig`
2. patch 前记原始哈希：`rahash2 -a sha256 sample.bin.orig`
3. 写模式打开并改字节：

   ```text
   r2 -w sample.bin
   s 0x1000          # 跳到目标地址
   wa nop            # 写汇编（arm64 分支用 b/bl，x86 用 jmp 等）
   wx 1f2003d5       # 或直接写原始字节
   wq                # 写入并退出
   ```

4. **patch 后 MUST 做字节级差分，证明只改了预期字节**：
   - `radiff2 sample.bin.orig sample.bin` — 确认改动的偏移/字节数与意图一致，无额外改动
   - `rahash2 -a sha256 sample.bin.orig sample.bin` — 对比前后哈希（必然不同；用于固定「哪个文件是哪个版本」并入 Evidence）
5. 仅「再反汇编看一眼」**不算验证**：反汇编只看目标点，看不出别处是否被误改。MUST 以 `radiff2` 的差分清单为准。

常见写操作：

- `wa <asm>`：写汇编
- `wx <hex>`：写原始字节
- `wq`：写入并退出

## 工作流 6：非交互自动化

适合一次性输出结果：

```text
r2 -A -q -c "afl;iz;ii;q" sample.bin
```

常用参数：

- `-A`：启动时自动分析
- `-q`：安静模式
- `-c`：执行命令串

如果命令很多，优先整理成易读顺序，不要塞入难以维护的超长串。

更推荐先用内置侦察脚本打底，再决定要不要补定制命令。

## 常用子工具

### `rabin2`

适合静态信息提取：

```text
rabin2 -I sample.bin   # 基本信息
rabin2 -S sample.bin   # 节区
rabin2 -s sample.bin   # 符号
rabin2 -i sample.bin   # 导入
rabin2 -E sample.bin   # 导出
rabin2 -z sample.bin   # 字符串
rabin2 -zz sample.bin  # 更详细字符串
```

### `rasm2`

适合快速汇编/反汇编：

```text
rasm2 -d "9090"
rasm2 -a x86 -b 64 "xor eax, eax"
```

### `radiff2`

适合对比两个二进制：

```text
radiff2 old.bin new.bin
radiff2 -C old.bin new.bin
```

### `rahash2`

适合算哈希：

```text
rahash2 -a md5 sample.bin
rahash2 -a sha256 sample.bin
```

### `rax2`

适合进制和编码转换：

```text
rax2 0x401000
rax2 4198400
rax2 -s hello
```

## 推荐分析顺序

遇到未知样本时，按这个顺序做：

1. `rabin2 -I` 看格式、架构、入口点
2. `rabin2 -z` 看字符串
3. `rabin2 -i` 看导入函数 — **MUST + Evidence（硬门，见工作流 1）**
4. 如需交互分析，再进 `r2`（仅当步骤 3 的 Evidence 已落盘）
5. 先 `aaa`，再 `afl` / `iz` / `pdf`
6. 通过字符串引用、导入调用、入口流程逐步定位关键函数

这个顺序的好处是噪音低，能尽快建立方向感。步骤 3 不是可选优化，是进入深挖前的硬门。

## 路径与环境注意事项

- 路径里有空格时，命令必须正确加引号
- 如果当前终端找不到 `r2`，可能是 `PATH` 刚更新，开一个新终端再试（本机 r2 在 `~/.local/bin`）
- 有些样本需要提权（root/管理员）才能读取，但默认不要主动提权，除非用户明确需要
- 对可疑样本做动态调试前，要先确认用户意图，避免误操作

## 输出风格

当用户不是只要命令，而是要你实际分析文件时：

- 先给出侦察结果摘要
- 再列出关键证据：字符串、导入、函数、地址
- 最后给出下一步建议或继续深入分析

不要只罗列命令而不解释为什么这么做。

## 典型请求示例

### 示例 1：分析一个 exe

用户：`帮我看看这个 exe 干了什么，用 radare2 就行`

处理方式：

1. 先用 `rabin2 -I/-z/-i`
2. 判断是否需要进入 `r2`
3. 用 `aaa`、`afl`、`pdf` 深挖入口和关键字符串引用

### 示例 2：找字符串在哪被调用

用户：`这个报错字符串在哪个函数里触发的`

处理方式：

1. 用 `iz~关键字` 找字符串地址
2. 用 `axt <addr>` 找引用
3. 跳到引用点 `s <addr>` 后 `pdf`

### 示例 3：改掉跳转

用户：`把这个 jne 改成 je`

处理方式：

1. 先确认目标地址
2. **先备份**：`cp sample.bin sample.bin.orig`，并记 `rahash2 -a sha256 sample.bin.orig`
3. 明确告知要进入写模式
4. 用 `wa je <target>` 或直接 `wx`
5. **字节级验证**（MUST）：`radiff2 sample.bin.orig sample.bin` 确认只改了那一条跳转的字节，无旁改；`rahash2 -a sha256 sample.bin.orig sample.bin` 固定前后版本入 Evidence。再反汇编只是补充，不能代替差分。

## 避免的做法

- 不要把 `radare2` 当成只有 `aaa` 一个命令的工具
- 不要在未说明风险时直接写模式打开用户文件
- 不要在还没做基础侦察前就下结论
- **禁止跳过导入表检查**（`rabin2 -i` / recon imports）：未写入 Evidence 不得进入下一步；用户要求重做导入表时禁止改做其他步骤
- **禁止 IAT 修复失败后静态死磕**：记 `E-iat-repair-fail` 后转动态；禁止 64 位样本只用 ImportREC
- 不要把网页 JS 逆向误导到这个 skill；那是 `reverse-engineering` 的范围

## 参考资料

- 命令速查：`references/cheatsheet.md`
- 标准侦察脚本：`scripts/recon.sh`

## radare2-skills 生态

radare2-skills 项目（radareorg/radare2-skills）提供了更完整的生态工具和工作流：

- **r2xsql**：SQL 查询二进制导入表 / 字符串 / 函数
- **r2mcp / r2http**：MCP 工具与 HTTP 状态化命令通道
- **radius2**：符号执行、符号动态分析
- **r2pm**：插件管理、扩展
- **decompiler plugins**：radare2 插件机制

**使用策略**：
- 当用户提到 `r2xsql`、`r2mcp`、`r2http`、`radius2`、`r2pm`、`rabin2`、`rasm2`、`radiff2`、`rahash2`、`rax2` 时，优先路由到本 skill（radare2/SKILL.md）
- 这些工具只是生态加速器，**不能绕过**：授权门禁、工具路径校验（`which`/`--version`）、Evidence 导入、写模式确认
- 给出最小可复现命令示例：
  - `r2xsql -s <file> -q "SELECT ..."`
  - `curl -sS --data-binary 'aaa' http://127.0.0.1:9393/cmd`
  - `radius2 -p <binary> ...`
  - `r2pm -ci <plugin>`

本 skill 保持原有硬门禁和证据链完整性，不允许跳过任何授权或 Evidence 步骤。

---

## 相关模块（本 setup）

- 需反编译/伪代码 → 先用 r2 内置 `pdg`（r2ghidra 已装，真正的 Ghidra 伪 C）；更重的工作再转 `ghidra-reverse/`（IDA 作为独立 skill 未安装）
- 需动态分析（Frida/GDB/lldb）→ `reverse-engineering/tools-dynamic.md`
- Mach-O / macOS 专项 → `macos-reverse/`
- Go/Rust 剥离二进制 → `go-rust-reverse/`
- 恶意样本流程与 Cloud/Isolation-Gates → `malware-analysis/`

## 安装（缺 radare2 时）

本地缺 radare2 时直接本地安装，不猜路径：

- macOS: `brew install radare2`
- Linux: `apt install radare2` 或从源码 `git clone https://github.com/radareorg/radare2 && sys/install.sh`
- 安装后用 `which r2` / `r2 -v` 确认路径

（本 setup 无自动 bootstrap-脚本；旧的 Windows-ZIP-自举表已移除，因为它只针对 Windows。）


## 任务完成自检（声称完成前 MUST 通过）

- [ ] 我是否执行了工作流中的每一步（而不是只阅读）？
- [ ] 导入表检查是否已执行且写入 Evidence（E-imports / E-triage-imports 或 .NET 等价）？DLL/SYS 是否含 E-exports？
- [ ] IAT 修复失败是否记录 E-iat-repair-fail 并转动态？重做请求是否回到同一步？
- [ ] 我是否用 `which` / `--version` 校验了真实工具路径？
- [ ] 我是否产出了可复现证据（命令/脚本/截图/报告）？
- [ ] 我是否完成并回写了 RULES 要求的 Checklist 项？
