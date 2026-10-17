# rev-agent

Autonomer Reverse-Engineering-Agent für Claude Code, für autorisierte, lokale
Analyse auf macOS (Apple Silicon). Zerlegt Ziele, um zu verstehen, wie sie
funktionieren: kompilierte Binaries (ELF/PE/Mach-O), APKs, Bytecode, gepackte
oder obfuskierte Loader, Firmware, Custom-VMs und verdächtige Samples. Ablauf
triage, static, dynamic, synthesis, report, mit durchgehender Beweiskette
Evidence zu Finding zu Path.

## Inhalt

- `agents/reverse-engineer.md`: der Agent selbst, mit harten Regeln,
  Skill-Routing und Pitfall-Checkliste.
- `agents/reverse-engineer-skeptiker.md`: adversarialer Review-Agent, der
  RE-Befunde und das Setup gnadenlos auf Fehler prüft.
- `skills/`: neun Skills, die der Agent je nach Ziel lädt (reverse-engineering,
  radare2, ghidra-reverse, go-rust-reverse, macos-reverse, malware-analysis,
  ctf-pwn, re-decompose, tool-clone).

## Installation

1. Agent und Skills nach `~/.claude` kopieren: `agents/*` nach
   `~/.claude/agents/`, jeden Ordner aus `skills/` nach `~/.claude/skills/`.
2. Lokale Tools nach Bedarf: radare2 (plus r2ghidra für echtes Pseudo-C),
   optional angr, capa, GoReSym. Der Agent prüft Pfade vor Nutzung und nennt den
   Installationsweg, wenn ein Tool fehlt.
3. Für nicht-native Ziele die REA-Tool-Ebene installieren:
   `npx -y rea-agents@latest setup`. REA ist nicht Teil dieses Repos.

## Routing nativ vs. nicht-nativ

- Nativ (ELF/PE/Mach-O, Go/Rust): lokale Route über radare2, r2ghidra, angr,
  capa, GoReSym.
- Nicht-nativ (JavaScript/Electron, .NET, Android-APK, EVM, Web-Captures,
  Mach-O-Triage ohne Engine): über REA, sobald installiert.

## Scope

Nur autorisierte, lokale Ziele: isolierte Sandbox, CTF, crackme, eigenes Sample,
Lab. Unbekannte Samples nie blind ausführen, nur isoliert auf einer Kopie.
Gefundene Secrets im Report nur maskiert. Kein Befund ohne reproduzierbaren
Beleg.

## Lizenz

MIT, siehe `LICENSE`. Herkunft der angepassten Skills und der externen
REA-Ebene steht in `ATTRIBUTION.md`.
