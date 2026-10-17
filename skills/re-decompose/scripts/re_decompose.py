#!/usr/bin/env python3
"""
re_decompose.py -- function-wise ("cell-level") decomposition of a binary.

Idea: split a binary into per-function units (decompile text + disassembly +
basic blocks + callees + xrefs) and emit them bottom-up over the call graph
(leaf functions first). A reversing agent loads one function at a time, keeps
the context window small, and feeds callee summaries up into the callers.

Backend: radare2, driven over the r2pipe protocol. Uses the r2pipe python
package if present, otherwise a dependency-free built-in pipe that speaks the
same \\x00-terminated protocol to the `r2` binary directly.

Output:
  --out-dir DIR   writes DIR/index.json, DIR/functions.jsonl and
                  DIR/func/NNNN_<name>.json  (NNNN = bottom-up rank)
  default         prints functions.jsonl to stdout

This tool only reads a local binary. It never executes the target.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import re


# --------------------------------------------------------------------------
# r2 driver
# --------------------------------------------------------------------------
class R2:
    """Minimal r2pipe-style driver. Prefers the r2pipe package, else talks
    the \\x00 protocol to the r2 binary over a pipe directly."""

    def __init__(self, path, r2bin="r2", flags=("-2",)):
        self.path = path
        self._pipe = None
        self._proc = None
        # 1) real r2pipe package if importable
        try:
            import r2pipe  # type: ignore
            self._pipe = r2pipe.open(path, flags=list(flags))
            self.backend = "r2pipe"
            return
        except Exception:
            self._pipe = None
        # 2) built-in pipe to the r2 binary
        exe = shutil.which(r2bin) or r2bin
        self._proc = subprocess.Popen(
            [exe, "-q0", "-2", path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        self.backend = "builtin"
        self._read_until_nul()  # consume startup banner

    def _read_until_nul(self):
        buf = bytearray()
        while True:
            ch = self._proc.stdout.read(1)
            if not ch:
                break
            if ch == b"\x00":
                break
            buf += ch
        return buf.decode("utf-8", "replace")

    def cmd(self, c):
        if self._pipe is not None:
            return self._pipe.cmd(c) or ""
        self._proc.stdin.write((c + "\n").encode())
        self._proc.stdin.flush()
        return self._read_until_nul()

    def cmdj(self, c):
        out = self.cmd(c).strip()
        if not out:
            return None
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return None

    def quit(self):
        try:
            if self._pipe is not None:
                self._pipe.quit()
            else:
                self._proc.stdin.write(b"q\n")
                self._proc.stdin.flush()
                self._proc.terminate()
        except Exception:
            pass


# --------------------------------------------------------------------------
# extraction helpers
# --------------------------------------------------------------------------
def pick(d, *keys, default=None):
    for k in keys:
        if isinstance(d, dict) and k in d and d[k] is not None:
            return d[k]
    return default


def detect_decompiler(r2):
    """Return the best available pseudo-C command: pdg (r2ghidra), pdc
    (built-in), or None -- via a real capability probe, not a truthy guard.

    Why a probe: r2's cmd() returns "" (never None) even for unknown commands,
    so `if r2.cmd("pdc?") is not None` is always true and tests nothing. We
    instead inspect what each help command actually reports.

    pdg: when r2ghidra is NOT loaded, `pdg?` answers with an install hint
    ("You need to install the plugin with r2pm -ci r2ghidra"). When loaded it
    prints a real `Usage: pdg...` help. So pdg is available iff the help is
    non-empty and carries no install/not-found marker.

    pdc: the built-in. Confirmed by its help advertising a "pseudo"-decompiler.
    Note r2 itself labels pdc "experimental, unreliable and hacky" -- the
    caller must treat pdc output as a hint, never as proof (see SKILL.md)."""
    pdg_help = (r2.cmd("pdg?") or "").strip().lower()
    neg = ("r2pm", "install the plugin", "not found", "unknown command",
           "cannot find")
    if pdg_help and not any(m in pdg_help for m in neg):
        return "pdg"
    pdc_help = (r2.cmd("pdc?") or "").lower()
    if "pseudo" in pdc_help:
        return "pdc"
    return None


def func_disasm(r2, addr):
    """Compact disassembly: list of 'offset  mnemonic operands'."""
    j = r2.cmdj("pdfj @ %s" % addr)
    if not j or "ops" not in j:
        return [], {}
    lines = []
    for op in j["ops"]:
        off = pick(op, "addr", "offset")
        txt = pick(op, "disasm", "opcode", default="")
        if off is None or not txt:
            continue
        lines.append("0x%x  %s" % (off, txt))
    meta = {
        "name": j.get("name"),
        "size": j.get("size"),
        "ninstr": len(j.get("ops", [])),
    }
    return lines, meta


def func_pseudo_c(r2, addr, cmd):
    if not cmd:
        return None
    txt = r2.cmd("%s @ %s" % (cmd, addr))
    if not txt:
        return None
    txt = txt.strip("\n")
    return txt if txt.strip() else None


def func_basic_blocks(r2, addr):
    j = r2.cmdj("afbj @ %s" % addr) or []
    bbs = []
    for b in j:
        bbs.append({
            "addr": b.get("addr"),
            "size": b.get("size"),
            "ninstr": b.get("ninstr"),
            "jump": b.get("jump"),
            "fail": b.get("fail"),
        })
    return bbs


def func_callees(r2, addr, fn_by_addr):
    """Return callees as list of {addr, name, internal} -- only real CALL
    references.

    PRIMARY path is `afxj` (function xrefs). In current radare2 (verified on
    6.2.4) `afij` no longer emits a `callrefs` field at all, so the old
    "afij-first, afxj as fallback" design silently produced zero callees from
    afij and relied entirely on the fallback. We therefore read afxj first.

    `afij` callrefs is kept only as a best-effort supplement for older r2
    builds that still populate it; it is NOT a robustness guarantee and is
    empty on modern r2. Indirect/virtual calls (fn pointers, vtables, blr x8)
    appear as ICOD/CODE, not CALL, so they are intentionally excluded here --
    the call graph is then incomplete (documented limitation in SKILL.md)."""
    out = []
    seen = set()

    def add_target(t, typ):
        if t is None:
            return
        typ = (typ or "").lower()
        # only real calls; "code" xrefs are intra-function jumps/branches
        if "call" not in typ:
            return
        if t in seen:
            return
        seen.add(t)
        internal = t in fn_by_addr
        out.append({
            "addr": t,
            "name": fn_by_addr.get(t, r2_flag_name(r2, t)),
            "internal": internal,
        })

    # primary: afxj carries the CALL xrefs on modern r2
    for ref in (r2.cmdj("afxj @ %s" % addr) or []):
        add_target(pick(ref, "to", "ref", "addr"), pick(ref, "type"))
    # legacy supplement: afij.callrefs (absent on r2 >= ~6.x, harmless if so)
    info = r2.cmdj("afij @ %s" % addr) or []
    if info:
        rec = info[0] if isinstance(info, list) else info
        for ref in rec.get("callrefs", []) or []:
            add_target(pick(ref, "addr", "to", "ref"), pick(ref, "type"))
    return out


_flag_cache = {}


def r2_flag_name(r2, addr):
    if addr in _flag_cache:
        return _flag_cache[addr]
    name = r2.cmd("fd %s" % addr).strip().split("\n")[0].strip()
    name = name or ("0x%x" % addr)
    # 'fd' may answer like 'sym.imp.printf + 0'; keep the symbol part
    name = name.split(" +")[0].strip()
    _flag_cache[addr] = name
    return name


def func_xrefs_to(r2, addr, fn_by_addr):
    out = []
    for ref in (r2.cmdj("axtj @ %s" % addr) or []):
        frm = pick(ref, "from", "addr")
        out.append({
            "from": frm,
            "fcn": ref.get("fcn_name") or fn_by_addr.get(ref.get("fcn_addr")),
            "type": ref.get("type"),
        })
    return out


# --------------------------------------------------------------------------
# bottom-up ordering (SCC-aware, handles recursion / mutual recursion)
# --------------------------------------------------------------------------
def scc_tarjan(nodes, edges):
    """edges: dict node -> set(callee nodes). Returns list of SCCs in reverse
    topological order (an SCC appears AFTER all SCCs it points to, i.e. its
    callees come first -> bottom-up).

    ITERATIVE Tarjan with an explicit work stack. The previous version used
    recursion plus sys.setrecursionlimit(10000); that only raises Python's
    counter, it does NOT grow the C stack, so a deep/linear call graph -- the
    exact workload this skill advertises -- could overflow the C stack and
    segfault the interpreter. This explicit-stack form has no such ceiling.

    It is a faithful replica of the recursive DFS: same node-visit order (over
    `nodes`), same successor-visit order (over each node's edge set), and the
    same SCC emission order. Therefore `in_cycle` (SCC membership + self-loops)
    and the bottom-up order built on top are identical to the recursive form;
    only the stack discipline changed."""
    index = {}
    low = {}
    onstack = set()
    comp_stack = []       # Tarjan's node stack (current path + pending SCC)
    sccs = []
    counter = 0

    for root in nodes:
        if root in index:
            continue
        # work stack frames: [node, successor_list, next_successor_pos]
        work = [[root, None, 0]]
        while work:
            frame = work[-1]
            v = frame[0]
            if frame[1] is None:
                # first entry into v: assign index/low, push onto Tarjan stack
                index[v] = low[v] = counter
                counter += 1
                comp_stack.append(v)
                onstack.add(v)
                frame[1] = list(edges.get(v, ()))  # snapshot successor order
            succ = frame[1]
            recursed = False
            i = frame[2]
            while i < len(succ):
                w = succ[i]
                if w not in index:
                    # descend into w (equivalent to the recursive call)
                    frame[2] = i + 1
                    work.append([w, None, 0])
                    recursed = True
                    break
                if w in onstack:
                    low[v] = min(low[v], index[w])
                i += 1
            if recursed:
                continue
            # all successors of v processed -> v's subtree is complete
            if low[v] == index[v]:
                comp = []
                while True:
                    w = comp_stack.pop()
                    onstack.discard(w)
                    comp.append(w)
                    if w == v:
                        break
                sccs.append(comp)
            work.pop()
            # propagate low to the caller, as "low[parent]=min(low[parent],
            # low[v])" would after a recursive return
            if work:
                p = work[-1][0]
                low[p] = min(low[p], low[v])
    # Tarjan emits SCCs in reverse-topological order: a component is finalized
    # only after its callees -> callees first. That is bottom-up.
    return sccs


def bottom_up_order(functions):
    """functions: list of dicts with 'addr' and 'callees'. Returns ordered
    list of addrs (leaves first) plus a set of addrs that are in a cycle."""
    fn_addrs = {f["addr"] for f in functions}
    edges = {}
    for f in functions:
        tgts = set()
        for c in f["callees"]:
            # keep self-edges: they mark direct recursion for cycle detection
            if c.get("internal") and c["addr"] in fn_addrs:
                tgts.add(c["addr"])
        edges[f["addr"]] = tgts
    sccs = scc_tarjan(list(fn_addrs), edges)
    order = []
    in_cycle = set()
    for comp in sccs:
        # self-loop (direct recursion) also counts as a cycle
        is_cycle = len(comp) > 1
        for v in comp:
            if v in edges.get(v, ()):
                is_cycle = True
        if is_cycle:
            in_cycle.update(comp)
        for v in sorted(comp):  # stable within component
            order.append(v)
    return order, in_cycle


# --------------------------------------------------------------------------
# main pipeline
# --------------------------------------------------------------------------
def analyze(path, r2bin, analysis_cmd, do_decompile, max_bytes, verbose):
    r2 = R2(path, r2bin=r2bin)
    log = (lambda *a: print(*a, file=sys.stderr)) if verbose else (lambda *a: None)
    log("[*] backend:", r2.backend)

    info = r2.cmdj("ij") or {}
    bininfo = {
        "file": os.path.abspath(path),
        "format": pick(info.get("core", {}), "format"),
        "arch": pick(info.get("bin", {}), "arch"),
        "bits": pick(info.get("bin", {}), "bits"),
        "os": pick(info.get("bin", {}), "os"),
        "lang": pick(info.get("bin", {}), "lang"),
    }
    log("[*] analyzing (%s) ..." % analysis_cmd)
    r2.cmd(analysis_cmd)

    decomp_cmd = detect_decompiler(r2) if do_decompile else None
    log("[*] decompiler:", decomp_cmd or "none (disasm only)")

    flist = r2.cmdj("aflj") or []
    fn_by_addr = {}
    for f in flist:
        a = pick(f, "addr", "offset")
        if a is not None:
            fn_by_addr[a] = f.get("name")
    log("[*] functions:", len(flist))

    functions = []
    for f in flist:
        addr = pick(f, "addr", "offset")
        if addr is None:
            continue
        size = f.get("size") or 0
        truncated = max_bytes and size > max_bytes
        disasm, meta = ([], {}) if truncated else func_disasm(r2, addr)
        pc = None if truncated else func_pseudo_c(r2, addr, decomp_cmd)
        rec = {
            "name": f.get("name"),
            "addr": addr,
            "addr_hex": "0x%x" % addr,
            "size": size,
            "nbbs": f.get("nbbs"),
            "nargs": f.get("nargs"),
            "nlocals": f.get("nlocals"),
            "stackframe": f.get("stackframe"),
            "signature": f.get("signature") or (r2.cmd("afcf @ %s" % addr).strip() or None),
            "pseudo_c": pc,
            # which decompiler actually produced pseudo_c: "pdg" (r2ghidra) or
            # "pdc" (built-in, experimental) or None. Lets the agent judge how
            # much to trust pseudo_c -- pdc is a hint, not proof (see SKILL.md).
            "decompiler_used": decomp_cmd if pc else None,
            "disasm": disasm,
            "basic_blocks": func_basic_blocks(r2, addr),
            "callees": func_callees(r2, addr, fn_by_addr),
            "xrefs_to": func_xrefs_to(r2, addr, fn_by_addr),
            "truncated": bool(truncated),
            # placeholder the agent fills while walking bottom-up
            "summary": None,
        }
        functions.append(rec)

    order, in_cycle = bottom_up_order(functions)
    rank = {a: i for i, a in enumerate(order)}
    for rec in functions:
        rec["rank"] = rank.get(rec["addr"])
        rec["in_cycle"] = rec["addr"] in in_cycle
    functions.sort(key=lambda r: (r["rank"] is None, r["rank"]))

    r2.quit()
    return {
        "bininfo": bininfo,
        "backend": r2.backend,
        "decompiler": decomp_cmd,
        "order_hex": ["0x%x" % a for a in order],
        "count": len(functions),
    }, functions


def safe_name(name, addr):
    base = re.sub(r"[^A-Za-z0-9_.]+", "_", name or "fcn")
    return "%s_0x%x" % (base[:60], addr)


# matches exactly the per-function filenames this tool writes: NNNN_<name>.json
_FUNC_FILE_RE = re.compile(r"^\d{4,}_.+\.json$")


def clean_func_dir(fdir):
    """Drop stale per-function JSON from a PREVIOUS run before writing this one.

    Why: func/ filenames encode the bottom-up rank + function name/addr, which
    differ between binaries, so a smaller target does NOT overwrite a larger
    earlier one -- the old files survive as orphans. index.json then reports the
    new (small) count while func/ holds both sets, with duplicate ranks (0000_*
    twice). An agent reading func/ would treat a previous binary's functions as
    current findings. We therefore wipe func/ so that after every run
    index.count == number of func/*.json files.

    Conservative on purpose:
      * only files DIRECTLY in fdir, never recursive;
      * only names this tool itself emits (NNNN_<name>.json);
      * hidden dotfiles (e.g. macOS .DS_Store) are ignored, not deleted;
      * if any other (non-hidden) entry exists -- a subdir or a foreign file --
        we refuse and abort instead of deleting a directory we don't own.
    """
    if not os.path.isdir(fdir):
        return
    visible = [n for n in os.listdir(fdir) if not n.startswith(".")]
    # layout check: every visible entry must be a regular file we produced
    for name in visible:
        full = os.path.join(fdir, name)
        if not (os.path.isfile(full) and _FUNC_FILE_RE.match(name)):
            raise SystemExit(
                "re_decompose: refusing to clean %s -- unexpected entry %r. "
                "Point -o at an empty directory or a previous re_decompose "
                "output dir." % (fdir, name)
            )
    for name in visible:
        os.remove(os.path.join(fdir, name))


def main():
    ap = argparse.ArgumentParser(description="Function-wise bottom-up decomposition of a binary (radare2).")
    ap.add_argument("binary", help="path to the local target binary")
    ap.add_argument("-o", "--out-dir", help="write index.json + functions.jsonl + func/*.json here")
    ap.add_argument("--r2", default="r2", help="r2 binary (default: r2 on PATH)")
    ap.add_argument("--analysis", default="aaa", help="r2 analysis command (aa/aac/aaa/aaaa, default aaa)")
    ap.add_argument("--no-decompile", action="store_true", help="skip pseudo-C, disassembly only")
    ap.add_argument("--max-bytes", type=int, default=0, help="skip disasm/decompile for functions larger than N bytes (0=no limit)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.binary):
        ap.error("no such file: %s" % args.binary)

    index, functions = analyze(
        args.binary, args.r2, args.analysis,
        not args.no_decompile, args.max_bytes, args.verbose,
    )

    if args.out_dir:
        fdir = os.path.join(args.out_dir, "func")
        os.makedirs(fdir, exist_ok=True)
        # wipe a previous run's func/*.json so index.count == #func files
        clean_func_dir(fdir)
        with open(os.path.join(args.out_dir, "functions.jsonl"), "w") as fh:
            for rec in functions:
                fh.write(json.dumps(rec) + "\n")
        for rec in functions:
            fn = "%04d_%s.json" % (rec.get("rank") if rec.get("rank") is not None else 9999,
                                   safe_name(rec["name"], rec["addr"]))
            with open(os.path.join(fdir, fn), "w") as fh:
                json.dump(rec, fh, indent=2)
        with open(os.path.join(args.out_dir, "index.json"), "w") as fh:
            json.dump(index, fh, indent=2)
        print("wrote %d functions to %s" % (len(functions), args.out_dir))
        print("  index.json, functions.jsonl, func/NNNN_<name>.json")
    else:
        for rec in functions:
            print(json.dumps(rec))


if __name__ == "__main__":
    main()
