#!/usr/bin/env bash
# recon.sh — radare2 快速侦察（二进制基本信息、节区、导入导出、字符串）
#
# 用法:
#   bash recon.sh <target_file> [--strings-limit 40] [--imports-limit 80] [--analyze]

set -euo pipefail

# ─── 参数 ──────────────────────────────────────────────────────────────────────────

TARGET=""
STRINGS_LIMIT=40
IMPORTS_LIMIT=80
RUN_ANALYSIS=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --strings-limit) STRINGS_LIMIT="$2"; shift 2 ;;
        --imports-limit) IMPORTS_LIMIT="$2"; shift 2 ;;
        --analyze) RUN_ANALYSIS=true; shift ;;
        -*) echo "未知选项: $1"; exit 1 ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "用法: $0 <target_file> [--strings-limit N] [--imports-limit N] [--analyze]"
    exit 1
fi

if [[ ! -f "$TARGET" ]]; then
    echo "ERR: 文件不存在: $TARGET"
    exit 1
fi

# ─── 工具检测 ──────────────────────────────────────────────────────────────────────

ensure_tool() {
    local name="$1"
    if command -v "$name" &>/dev/null; then
        return 0
    fi
    echo "ERR: $name 未找到。请本地安装 radare2 后重试："
    echo "     macOS: brew install radare2"
    echo "     Linux: apt install radare2（或 git clone radareorg/radare2 && sys/install.sh）"
    exit 1
}

ensure_tool "rabin2"
[[ "$RUN_ANALYSIS" == "true" ]] && ensure_tool "r2"

# ─── 绝对路径 ──────────────────────────────────────────────────────────────────────

TARGET="$(realpath "$TARGET")"
echo "目标文件: $TARGET"

# ─── 侦察 ─────────────────────────────────────────────────────────────────────────

echo ""
echo "=== 基本信息 ==="
rabin2 -I -- "$TARGET"

echo ""
echo "=== 节区 ==="
rabin2 -S -- "$TARGET"

echo ""
echo "=== 导入 ==="
rabin2 -i -- "$TARGET" | head -n "$IMPORTS_LIMIT"

echo ""
echo "=== 导出 ==="
rabin2 -E -- "$TARGET"

echo ""
echo "=== 字符串 ==="
rabin2 -zz -- "$TARGET" | head -n "$STRINGS_LIMIT"

if [[ "$RUN_ANALYSIS" == "true" ]]; then
    echo ""
    echo "=== 函数与入口分析 ==="

    # 注意：entry0 在 stripped / arm64 Mach-O 上常无法解析——r2 打印
    # "Cannot seek to unknown address 'entry0'" 却仍以退出码 0 返回
    # （set -euo pipefail 捕不到），而且 -c 命令链在 seek 失败后会中止
    # 后续命令，导致本段静默为空。
    # 对策：先探测可用 seek 目标（entry0 → sym.main → main → rabin2 -e 入口
    # vaddr），全部失败则不 seek、直接全量 afl/iz/ii，并显式告警，保证本段永不静默。

    seek_ok() {
        # $1 = seek 目标；stderr 无 "Cannot seek" 即视为成功
        ! r2 -q -c "s $1" -- "$TARGET" 2>&1 >/dev/null | grep -qiE 'cannot seek'
    }

    SEEK_TARGET=""
    ENTRY_VADDR="$(rabin2 -e -- "$TARGET" 2>/dev/null | awk '/^0x/{print $2; exit}')"
    for cand in entry0 sym.main main "$ENTRY_VADDR"; do
        [[ -z "$cand" ]] && continue
        if seek_ok "$cand"; then SEEK_TARGET="$cand"; break; fi
    done

    if [[ -n "$SEEK_TARGET" ]]; then
        echo "[seek 目标: $SEEK_TARGET]"
        r2 -A -q -c "s $SEEK_TARGET;afl;iz;ii;q" -- "$TARGET"
    else
        echo "WARN: entry0 / sym.main / 入口 vaddr 均无法 seek（stripped 或 arm64 Mach-O 常见）；跳过 seek，直接全量分析" >&2
        echo "[seek 目标: 无（已跳过 seek）]"
        r2 -A -q -c 'afl;iz;ii;q' -- "$TARGET"
    fi

    # Funktionszahl prüfen: dieser r2 6.2.4-Build findet auf manchen arm64-Mach-O
    # 0 Funktionen (aaa greift nicht). Nicht still als "Übersicht erledigt" werten.
    FCOUNT="$(r2 -A -q -c 'aflc' -- "$TARGET" 2>/dev/null | tr -dc '0-9')"
    if [[ "${FCOUNT:-0}" == "0" ]]; then
        echo "WARN: 0 Funktionen erkannt (aaa griff nicht; r2-Build-Grenze auf arm64-Mach-O). Funktionsübersicht NICHT als erledigt werten — mit Ghidra/anderer Analyse gegenprüfen." >&2
    fi
fi
