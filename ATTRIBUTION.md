# Attribution

Dieses Repo bündelt eigene Arbeit und angepasste Skills aus MIT-lizenzierten
Projekten. Lizenz dieses Repos: MIT (siehe `LICENSE`). Die fremden Bestandteile
behalten ihre jeweilige Lizenz.

## Eigene Arbeit (MIT, Sami Magdouli)

- `agents/reverse-engineer.md`
- `agents/reverse-engineer-skeptiker.md`
- `skills/re-decompose`
- `skills/tool-clone`

## Angepasst aus Dritt-Projekten (MIT)

- `skills/reverse-engineering`, `skills/radare2`, `skills/ghidra-reverse`,
  `skills/go-rust-reverse`, `skills/macos-reverse`, `skills/malware-analysis`
  adaptiert aus `zhaoxuya520/reverse-skill` (GitHub, MIT).
- `skills/ctf-pwn` adaptiert aus `ljagiello/ctf-skills` (GitHub, MIT). Die
  Copyright-Notice liegt als `skills/ctf-pwn/LICENSE` bei.

## Nicht enthalten, extern installiert

- Die REA-Tool-Ebene (`reverse-engineer-anything`, MCP + Skill) gehört
  `morluto/rea` (MIT) und wird NICHT mit ausgeliefert. Installation über
  `npx -y rea-agents@latest setup`. Der Agent routet nicht-native Ziele an REA,
  sobald es installiert ist.
