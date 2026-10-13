---
name: macos-reverse
description: Use for authorized macOS and Mach-O reverse engineering including codesign, Objective-C/Swift recovery, endpoint security surfaces, and Apple platform malware analysis.
---

# macOS / Mach-O Reverse Engineering

## ACTION REQUIRED（读完后立刻执行）

1. `NOW`: 仅在本地、已授权的 Sandbox 上工作；可疑样本视为 untrusted
2. `NOW`: 确认目标为 macOS/Mach-O/App bundle（iOS IPA 无专用 skill，在本 setup 复用本 skill 的 Mach-O 分支，动态优先 lldb）
3. `NEXT`: 用 `which` / `--version` 校验本地工具（codesign/otool/nm/spctl + lldb 系统自带，可直接用；Frida/jtool2/class-dump/dsdump/Hopper/swift-demangle 本 setup 未安装，用前必须 `which` 校验，缺则按工具链安装或改用自带工具）
4. `ACT`: 签名与装载信息 → 静态（自带 otool/nm 为主）→ 动态（lldb；Frida 未装时仅用 lldb）

## 适用场景

- Mach-O 可执行文件 / dylib / framework
- .app bundle、LaunchAgent/Daemon
- Objective-C / Swift 符号与 runtime
- 公证/签名、Hardened Runtime、TCC 相关行为分析
- macOS 恶意软件静态/动态分析（联合 malware-analysis）

## 工作流

### 1. 包体与签名

```bash
file target
codesign -dv --verbose=4 target
spctl -a -vv target 2>&1
otool -L target
```

### 2. 静态

```text
□ 主力用自带工具：otool -ov（ObjC 元数据）/ otool -s __TEXT __cstring / nm -m（符号）/ strings
□ class-dump / swift-demangle / Hopper / Ghidra / IDA 本 setup 均未安装（见工具链，用前 `which` 校验）
□ ObjC 头兜底用 `otool -ov`；Swift 名称 demangle 需额外工具（swift-demangle 未装；若装了 Xcode/CLT 可试 `xcrun swift-demangle`）
□ 字符串与 XPC 服务名、TCC 敏感 API
□ LC_LOAD_dylib 依赖与 rpath
```

### 3. 动态

```text
□ lldb（本 setup 自带，动态主力）；Frida 本 setup 未安装，用前 `which frida`，缺则仅用 lldb
□ fs_usage / log stream 观察
□ 网络：用代理（mitmproxy / Charles 等）抓流量；protocol-reverse 在本 setup 无独立 skill
```

## 工具链

| 工具 | 用途 | 安装 / 可用性 |
|------|------|------|
| otool / nm / codesign / spctl | 签名 / 符号 / 装载 / 静态 | 系统自带，直接用 |
| lldb | 动态主力 | 系统自带，直接用 |
| Hopper / Ghidra / IDA | 反编译 | **本 setup 未安装**（Ghidra 见 `../ghidra-reverse/` 的安装说明；Hopper/IDA 商业，手动安装） |
| class-dump / dsdump | ObjC 头 / 符号 | **本 setup 未安装**（brew 本身也未装，离线无法核实）；装前先确认 class-dump 的 Formula/Cask 是否存在（`brew info class-dump`，Formula 失败再试 `--cask`），再 `brew install class-dump`；dsdump 手动构建；兜底用 `otool -ov` |
| swift-demangle | Swift 名称还原 | **本 setup 未安装**；随 Xcode/CLT 时可试 `xcrun swift-demangle` |
| jtool2 | Mach-O 解析 | **本 setup 未安装**；手动下载；兜底用 `otool` / `nm` |
| Frida | 动态插桩 | **本 setup 未安装**；`pip install frida-tools`，用前 `which frida`；缺则仅用 lldb |

## 参考

- `references/macho-triage.md`
- `../ghidra-reverse/`（反编译）、`../malware-analysis/`（样本流程 + Cloud/Isolation-Gates）、`../radare2/`（CLI 侦察）
- （iOS/Mobile 作为独立 skill 在本 setup 未安装 → iOS IPA 复用本 skill 的 Mach-O 分支，动态优先 lldb；Frida 未装）

## 相关模块（本 setup）

- 通用样本流程 → `malware-analysis/`
- Go/Rust Mach-O → `go-rust-reverse/`

## 任务完成自检

- [ ] 是否记录签名/Hardened Runtime 状态？
- [ ] 是否有地址级/符号级结论？
- [ ] Checklist？