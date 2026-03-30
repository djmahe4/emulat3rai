---
name: emulat3rai-architect
description: >
  Use this skill to update, extend, and improve the emulat3rai codebase and analysis tools. 
  Focuses on codebase "improvisation": refactoring modules, adding API hooks to HookRegistry, 
  creating new analysis observers in src/skills/, or modifying EmulatorConfig/EmulatorSession.
  Enforces TDD closure (uv run pytest tests/) before any task is marked done.
  Do NOT use for performing reverse engineering on samples or choosing realism levels;
  use the emulat3rai-analyst skill instead.
risk: safe
category: architecture
tags: [emulator, architecture, hooks, observers, tdd, vivisect, modular-design]
date_added: "2026-03-30"
---

# emulat3rai-architect: Modular Architecture Protocol

Use this skill to extend, maintain, or migrate the `emulat3rai` codebase and improve 
its analysis capabilities.

## Cross-Platform Strategy & Modularity

> [!IMPORTANT]
> **Priority: Stability First.** Layer abstractions before implementing features.

To support Linux/ELF malware without breaking Windows stability, the following modular architecture must be followed:

### 1. ArchContext Abstraction
Wrap CPU state (Registers/Memory) in a generic interface.
- `get_register(name)` / `set_register(name, value)`
- `read_memory(addr, size)` / `write_memory(addr, data)`
- *Standard*: Use `platform/arch/x86_64/` for specific logic.

### 2. OS Abstraction Layer
- **`OSEmulator`**: Base class for `WindowsOSEmulator` and `LinuxOSEmulator`.
- **`SyscallTable`**: OS-specific lookup for `NtQuery` vs `sys_read`.
- **`FileObject`**: Abstract interface for Windows Handles (64-bit) vs Linux FDs (int).

### 3. Event/Hooking System
Maintain a generic `HookManager` that fires standardized events (`MEMORY_WRITE`, `PRE_SYSCALL`) regardless of the target OS.

---

## When to Use This Skill

- Adding a new Windows API hook to `src/hooks.py`.
- Creating a new analysis observer in `src/skills/`.
- Modifying `EmulatorConfig` fields in `src/config.py`.
- Extending `EmulatorSession` (checkpoint/rollback, serialization) in `src/session.py`.
- Modifying realism setup logic in `src/environment.py`.
- Performing any module-level refactor across `src/`.

## When NOT to Use This Skill

- Choosing realism levels or crash-mode strategies for a specific sample → use **emulat3rai-analyst**.
- Running the emulator on a malware file to help a user perform RE → use **emulat3rai-analyst**.
- General advice for the user on how to analyze a specific sample.

---

## 1. Module Map (Canonical Reference)

```
emulat3rai/
├── emulat3.py              # CLI entry point — do not add logic here
└── src/
    ├── config.py           # EmulatorConfig (dataclass) — all tunable knobs
    ├── emulator.py         # Core vivisect wrapper + step_emulator()
    ├── session.py          # EmulatorSession — high-level agent API
    │                       # - checkpoint() / rollback() via memory snapshots
    │                       # - export_json() for structured output
    ├── observers.py        # EventManager + BaseObserver interface
    │                       # - ALL events: EVT_INSTRUCTION, EVT_MEM_WRITE,
    │                       #   EVT_EXCEPTION, EVT_CALL, EVT_HOOK_FIRED, etc.
    ├── hooks.py            # HookRegistry — Windows API stubs
    │                       # - Architecture-aware arg extraction (x64/x86)
    ├── environment.py      # EnvironmentManager
    │                       # - Realism levels 0/1/2 (stack, PEB/TEB, heap)
    └── skills/             # Analysis observers (extend BaseObserver)
        ├── anti_loophole_detector.py  # REP-loop detection
        ├── deep_explore.py            # Call-tree mapping
        └── malware.py                 # Anti-debug / pattern detection
```

**Rule**: Never add analysis logic to `emulator.py` or `session.py`. Always add it as a new
observer in `src/skills/` and attach via `EventManager`.

---

## 2. Self-Healing Migration Protocol

Apply this protocol in order for every feature or refactor task:

1. **Gap Analysis** — Before writing any code, read:
   - `src/config.py` for current `EmulatorConfig` fields.
   - `src/session.py` for checkpoint/rollback state ownership.
   - Existing files in `src/skills/` to avoid duplicating patterns.

2. **Module-First Extension** — Do not touch `emulator.py` first.
   - New analysis logic → `src/skills/new_skill.py` extending `BaseObserver`.
   - New configuration knob → add field to `EmulatorConfig` in `config.py`.
   - New hook → register in `hooks.py` via `@registry.hook(...)`.

3. **State Integrity Check** — After any change to `session.py` or `config.py`:
   - Verify `checkpoint()` captures your new state field.
   - Verify `rollback()` restores it correctly.
   - Verify `export_json()` serializes it without `TypeError`.

4. **TDD Closure** — A task is **Done** only when:
   ```bash
   uv run pytest tests/
   ```
   shows **0 failures**. Write the failing test first (RED), then implement (GREEN).

---

## 3. Adding a New API Hook

Hook callbacks must be architecture-aware. `HookManager` auto-extracts arguments for x64
(RCX, RDX, R8, R9) and x86 (ESP+4, ESP+8, ...).

```python
# In src/hooks.py — inside build_default_registry()
from .hooks import HookRegistry

registry = HookRegistry()

@registry.hook("kernel32.VirtualAlloc")
def hook_virtual_alloc(manager, emu, name, args):
    # args[0] = lpAddress (RCX on x64)
    # args[1] = dwSize    (RDX on x64)
    # args[2] = flAllocationType
    # args[3] = flProtect
    size = args[1]
    # Allocate a real page in the emulator's memory space
    base = emu.allocateMemory(size)
    emu.writeMemory(base, b"\x00" * size)
    return base  # Return value goes into RAX/EAX
```

**Failure shield**: Always return a valid guest address (not 0) unless the real API is
expected to fail, or you will cause cascading NULL-dereference crashes.

---

## 4. Creating a New Analysis Observer

All observers extend `BaseObserver` from `src/observers.py`.
Override only the events you need.

```python
# src/skills/my_new_observer.py
from __future__ import annotations
from typing import Any
from ..observers import BaseObserver

class MyNewObserver(BaseObserver):
    """Detects XOR-key extraction patterns."""

    def __init__(self):
        self.xor_candidates: list[tuple[int, int]] = []

    def on_instruction(self, *, event: str, step: int, va: int, insn: str, emu: Any, **kw):
        if insn.strip().startswith("XOR") and "," in insn:
            parts = insn.split(",")
            dst, src = parts[0].split()[1], parts[1].strip()
            if dst != src:  # Not a register-clear idiom (XOR eax, eax)
                self.xor_candidates.append((va, step))

    def on_session_end(self, *, event: str, steps: int, va: int, config: Any, **kw):
        print(f"[XOR] {len(self.xor_candidates)} non-zero XOR ops detected.")
```

Register it in a session:
```python
from src.skills.my_new_observer import MyNewObserver
sess.set_observer(MyNewObserver())
```

---

## 5. Extending EmulatorConfig

Add new fields to the `EmulatorConfig` dataclass in `src/config.py`. Use `field(default=...)`:

```python
from dataclasses import dataclass, field

@dataclass
class EmulatorConfig:
    max_instructions: int = 200
    realism_level: int = 0
    crash_mode: str = "rollback"    # "rollback" | "partial" | "continue"
    repmax: int = 256
    follow_calls: bool = False
    follow_depth: int = 5
    stack_size: int = 524_288       # 512 KB default
    # NEW FIELD:
    entropy_detection: bool = False  # Enable entropy-based ransomware detection
```

After adding a field:
1. Update `session.py` if the field affects checkpoint/rollback.
2. Update `cliargs.py` if the field should be user-configurable.
3. Add a test in `tests/` that exercises the new behavior.

---

## 6. Recovery Implementation Reference

| Mode                | Config value    | Mechanism in `session.py`                                  |
|---------------------|-----------------|------------------------------------------------------------|
| Full Rollback       | `"rollback"`    | `sess.checkpoint()` → binary snapshot, `sess.rollback()`   |
| Partial (NOP-patch) | `"partial"`     | Memory writes kept, registers reset; crashing insn NOP'd   |
| Continue            | `"continue"`    | Exception logged, RIP advanced past fault address          |

**Always call `sess.checkpoint()` before entering high-risk branches.** Example:
```python
sess.checkpoint()
try:
    sess.run_until_va(suspicious_va)
except Exception:
    sess.rollback()  # Returns to the state before the bad call
```

---

## 7. Verification Command

Always run after any change to `src/`:

```bash
uv run pytest tests/ -v
```

Expected: `7 passed, 0 failed` (or more if new tests were added).
Task is **blocked** until this passes.
