---
name: emulat3rai-analyst
description: >
  Use this skill to help the user perform reverse engineering and behavioral analysis on 
  malware samples. Provides guidance on configuring realism levels, choosing crash recovery 
  modes, and synthesizing multiple analysis observers for maximum forensic signal.
  Focuses on the "how-to" of analysis for the end-user.
  Do NOT use for internal code refactoring or improvising the emulator tools;
  use the emulat3rai-architect skill instead.
risk: safe
category: malware-analysis
tags: [malware, emulation, forensics, vivisect, anti-analysis, realism, crash-recovery, observers]
date_added: "2026-03-30"
---

# emulat3rai-analyst: Maximizing Forensic Output

Use this skill to help the user extract the highest-fidelity forensic signal from the 
`emulat3rai` x64 emulator. The emulator wraps the `vivisect` engine and exposes a 
modular, observer-driven analysis pipeline for reverse engineers.

## Safe Sandbox Practices (Critical)

> [!CAUTION]
> **ALWAYS RUN `emulat3rai` WITHIN AN ISOLATED VIRTUAL MACHINE (VM) OR CONTAINER.**

Even with internal memory sandboxing, the risk of **"Leaky Emulation"** exists. Malicious code is designed to find flaws in execution environments.

### Risks of Leaky Emulation
- **Emulator Vulnerabilities**: Bugs in the emulation engine or underlying libraries (`Vivisect`) could be exploited to escape to the host.
- **Host OS Interaction**: Imperfections in file system or network mocks can allow malware to reach host resources.
- **Advanced Evasion**: Sophisticated malware may detect the emulator and trigger specific breakout exploits.

### Recommended Setup
1. **Dedicated VM**: Use VirtualBox, VMware, or QEMU.
2. **Network Isolation**: Use "Host-Only" or NAT without port forwarding. Block outbound internet by default.
3. **Snapshots**: Take a clean snapshot *before* analysis and revert immediately after.
4. **No Sensitive Data**: Never store personal or work credentials in the analysis environment.

---

## When to Use This Skill

- User wants to analyze a PE, DLL, or raw shellcode with `emulat3rai`.
- User is unsure which `--realism-level` to choose.
- User needs advice on `--crash-mode` (rollback/partial/continue).
- User wants to combine `AntiLoopholeDetector`, `DeepExploreObserver`, or `AntiDebugPattern`.
- User wants CLI command examples for common malware analysis scenarios.

## When NOT to Use This Skill

- Adding or modifying API hooks → use **emulat3rai-architect**.
- Refactoring `src/` modules (config, session, hooks, environment) → use **emulat3rai-architect**.
- Running unit tests or CI → use `uv run pytest tests/` directly.

---


## 1. Realism Level Decision Matrix

Set with `--realism-level {0,1,2}` on the CLI.

| Level | Stack         | PEB/TEB               | Heap            | FS/GS    | When to Choose |
|-------|---------------|-----------------------|-----------------|----------|----------------|
| **0** | Zero-filled   | None                  | None            | Not set  | Raw triage, packed/obfuscated input, performance-critical tracing |
| **1** | Entropy-filled| Stubs (BeingDebugged=0)| None           | GS→TEB   | General behavioral analysis, API call tracing, initial anti-debug checks |
| **2** | Entropy-filled| Full field population  | 1 MB fake heap | GS→TEB   | Advanced anti-VM/anti-sandbox, heap-spray analysis, PEB.NtGlobalFlag tricks |

### Choosing L0 — Raw Execution
Use L0 when:
- The sample is packed and you suspect the packer checks for environmental setup.
- You only need an instruction trace, not API-level behavior.
- You are measuring timing or performance.
- The sample crashes immediately at any other level (start at L0, escalate).

### Choosing L1 — Moderate Fidelity
Use L1 when:
- You want to observe Windows API calls with arguments.
- The sample checks `PEB.BeingDebugged` or `NtGlobalFlag` (common in commodity malware).
- You need a call graph without full PEB/heap overhead.

### Choosing L2 — High Fidelity
Use L2 when:
- The sample inspects PEB/TEB fields beyond `BeingDebugged` (e.g., `PEB.NtGlobalFlag == 0x70`).
- The sample performs heap-based fingerprinting or checks heap header consistency.
- The sample uses FS/GS segment register tricks to detect sandbox.
- Add `--stack-size 2097152` (2 MB) for heap-spray samples that need large memory headroom.

---

## 2. Crash Recovery Strategy

Set with `--crash-mode {rollback|partial|continue}`.

### `--crash-mode rollback` (Default)
- **Mechanism**: Restores full pre-crash memory + register snapshot via `sess.checkpoint()`.
- **Use when**: The crash signals state corruption that would taint all future analysis.
- **Use when**: You want to explore alternative execution paths from a known-good state.
- **Cost**: Higher memory overhead (full state snapshot), slower recovery.

### `--crash-mode partial`
- **Mechanism**: Keeps accumulated memory writes, resets only registers (NOP-patch on crash site).
- **Use when**: The crash is a deliberate anti-analysis trigger (div-by-zero, invalid access) you want to bypass.
- **Use when**: You want to continue execution from the current context without losing observed writes.
- **Risk**: May cause state inconsistencies if the patched instruction had critical side effects.

### `--crash-mode continue`
- **Mechanism**: Logs the exception and advances RIP past the faulting instruction.
- **Use when**: You need to maximize coverage and accept approximate results.
- **Use when**: The sample has frequent minor exceptions that are not analytically relevant.

---

---

## 3. Observer Synthesis & Signal Correlation

Observers live in `src/skills/`. Attach them via `EmulatorSession.set_observer()`. Combine them for multi-dimensional signal detection.

### Pattern A: Obfuscation & XOR-Loop Detection
**Observers**: `AntiLoopholeDetector` + `DeepExploreObserver`

- `AntiLoopholeDetector` flags REP-family instructions and "Hot Addresses" (high-visit counts).
- **Forensic Signal**: Correlate loop alerts with call-tree depth. A tight loop in a leaf function that writes to memory is a high indicator of an **XOR-unpacker stub**.
- **Tuning**: Adjust `warn_threshold` (default 50) to catch early-stage unpacking before it finishes.

### Pattern B: Anti-Analysis Neutralization
**Observers**: `AntiDebugPattern` + `AntiAnalysisPattern` | **Level**: 2

- `AntiDebugPattern` monitors for `IsDebuggerPresent`, `NtQueryInformationProcess`, etc.
- `AntiAnalysisPattern` detect VM artifacts and linearizes timing via `GetTickCount`.
- **Forensic Signal**: Determines what technique, where in execution flow, and which parent function triggered the check.
- **Force L2** to ensure PEB/TEB field values are accurate and all detection patterns trigger.

### Pattern C: Full Behavioral Profile
**Observers**: All three | **Level**: 1 or 2 | **Input variation**: `--follow-calls`

- Run all three observers concurrently with `--follow-calls` and `--follow-depth 3` for a high-fidelity execution trace.
- Vary command-line arguments using `sess.run_until_va(target_va)` for targeted branch coverage.
- **Forensic Signal**: Multi-dimensional profile reveals adaptive behavior under different inputs.

---

## 4. Verified CLI Workflows

All flags below are confirmed from `src/cliargs.py`.

### Workflow A: Rapid Triage (PE)
```bash
python emulat3.py \
  --pe malware.exe \
  --realism-level 1 \
  --max 500000 \
  --follow-calls \
  --follow-depth 3 \
  --json-output
```
Output: JSON summary with call tree and pattern hits. Save to `> triage.json`.

### Workflow B: Shellcode Triage
```bash
python emulat3.py \
  --sc-hex "4831c04889c7c3" \
  --realism-level 0 \
  --max 1000 \
  --json-output
```

### Workflow C: Deep Anti-Analysis Bypass (Packed DLL)
```bash
python emulat3.py \
  --pe packer.dll \
  --va 0x180001234 \
  --realism-level 2 \
  --stack-size 2097152 \
  --crash-mode rollback \
  --repmax 512 \
  --follow-calls \
  --follow-depth 5 \
  --json-output
```
- `--va`: Start at DllMain or known unpacker stub VA.
- `--repmax 512`: Allow larger REP loops without aborting.

### Workflow D: Bypass Minor Anti-Debug Triggers
```bash
python emulat3.py \
  --pe dropper.exe \
  --realism-level 1 \
  --crash-mode partial \
  --max 300000 \
  --json-output
```
NOP-patches deliberate crashes; continues scanning for C2 setup, dropper writes.

### Workflow E: Targeted Function Analysis
```bash
python emulat3.py \
  --pe target.dll \
  --va 0x180005678 \
  --realism-level 2 \
  --follow-va 0x180005700 \
  --max 50000 \
  --stack-context 8
```
- `--va` + `--follow-va`: Pinpoints a suspicious callee within a known function.
- `--stack-context 8`: Shows 8 QWORD entries above/below RSP for stack-inspection analysis.

---

## 5. Session API for Scripted Analysis

Use `EmulatorSession` when you need loop control or custom stop conditions.

```python
from src.session import EmulatorSession
from src.config import EmulatorConfig

cfg = EmulatorConfig(
    max_instructions=500_000,
    realism_level=2,
    crash_recovery="rollback",
)
sess = EmulatorSession(vw, emu, 0x140001000, cfg)

# Attach all observers
from src.skills.anti_loophole_detector import AntiLoopholeDetector
from src.skills.deep_explore import DeepExploreObserver
from src.skills.malware import AntiDebugPattern, AntiAnalysisPattern

sess.set_observer(AntiLoopholeDetector())
sess.set_observer(DeepExploreObserver())
sess.set_observer(AntiDebugPattern())
sess.set_observer(AntiAnalysisPattern())

# Snapshot before entering unpacker
sess.checkpoint()
sess.run()

# Export JSON summary
print(sess.export_json())
```

---

## 6. Failure Shields

- Never run L2 on a shellcode blob without a `--base` anchor — the fake heap may overlap.
- Do not use `--crash-mode continue` with `--follow-calls` on high-depth trees; coverage will be
  noisy and attributably incorrect.
- Verify the entry VA (`--va`) is a valid function boundary using `--list` first:
  `python emulat3.py --pe target.exe --list`
- Treat `AntiLoopholeDetector` alerts as hints, not conclusions; cross-check with `DeepExploreObserver`.
