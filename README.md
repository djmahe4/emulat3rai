# emulat3rai

> Modular, extensible, AI/agent-friendly x64 instruction-level emulator — a refactor of [whokilleddb/emulat3](https://github.com/whokilleddb/emulat3), built on the [vivisect](https://github.com/vivisect/vivisect) engine (used by Mandiant FLOSS).

Each step prints:
- Disassembled instruction
- All general-purpose registers + RIP + EFLAGS
- Stack contents around RSP
- Memory writes
- Exceptions (segfaults, invalid instructions, breakpoints)

---

## Architecture

```
emulat3rai/
├── emulat3.py          # CLI entry point
└── src/
    ├── config.py       # EmulatorConfig – all tunable knobs
    ├── emulator.py     # Core vivisect wrapper + step_emulator()
    ├── session.py      # EmulatorSession – high-level agent API
    ├── observers.py    # Observer/callback system
    ├── hooks.py        # API hooks registry (Windows API stubs)
    ├── environment.py  # PEB/TEB realism, FS/GS, stack setup
    ├── analyzer.py     # Static analysis helpers
    ├── pe.py           # PE loading + emulate_pe()
    ├── shellcode.py    # Shellcode loading + emulate_shellcode()
    ├── cliargs.py      # argparse parser
    ├── consts.py       # Constants (register names, EFLAGS, …)
    ├── misc.py         # Banner, hex parser, logging suppressor
    └── skills/
        ├── anti_loophole_detector.py
        └── deep_explore.py
```

---

## Install

Requires Python 3.12+.

```bash
# with uv (recommended)
uv sync

# or with pip
pip install vivisect viv-utils rich
```

---

## Usage

### PE mode

```bash
# Emulate from the entry point
python emulat3.py --pe xor.exe

# Emulate a specific function
python emulat3.py --pe xor.exe --va 0x140001010 --max 100

# List all functions in the binary
python emulat3.py --pe xor.exe --list

# Follow calls into a specific subroutine
python emulat3.py --pe xor.exe --va 0x1400014c1 --follow-va 0x140001450

# Follow all calls up to 3 levels deep
python emulat3.py --pe xor.exe --va 0x1400014c1 --follow-calls --follow-depth 3
```

### Shellcode mode

```bash
# Raw binary shellcode
python emulat3.py --shellcode payload.bin

# Hex-encoded file
python emulat3.py --shellcode encoded.txt --hex

# Inline hex string
python emulat3.py --sc-hex "4831c04889c7c3"

# \x notation also works
python emulat3.py --sc-hex "\x48\x31\xc0\xc3"
```

### Realism levels

```bash
# Level 0 (default) – minimal, zero-filled stack
python emulat3.py --pe malware.exe --realism-level 0

# Level 1 – randomised stack, PEB/TEB stubs, FS/GS base set
python emulat3.py --pe malware.exe --realism-level 1

# Level 2 – full PEB/TEB, fake heap with entropy, high-realism fingerprint resistance
python emulat3.py --pe malware.exe --realism-level 2 --stack-size 2097152
```

### Crash handling

```bash
# rollback (default) – restore full pre-crash snapshot
python emulat3.py --pe malware.exe --crash-mode rollback

# partial – keep memory writes, reset registers
python emulat3.py --pe malware.exe --crash-mode partial

# continue – log the crash and keep going
python emulat3.py --pe malware.exe --crash-mode continue
```

### JSON output

```bash
python emulat3.py --sc-hex "48C7C00A000000C3" --json-output
```

---

## Options

| Flag | Description |
|------|-------------|
| `--pe FILE` | PE file to analyze |
| `--va ADDR` | Function VA to emulate (hex) |
| `--list` | List all functions in the PE and exit |
| `--shellcode FILE` | Shellcode file (raw binary) |
| `--sc-hex HEX` | Inline hex shellcode string |
| `--hex` | Treat shellcode file as hex-encoded |
| `--base ADDR` | Shellcode base address (default: `0x690000`) |
| `--entry OFFSET` | Entry point offset from base (default: `0`) |
| `--max N` | Max instructions to execute (default: `200`) |
| `--follow-calls` | Step into call instructions |
| `--follow-va ADDR` | Only step into calls to this specific address |
| `--follow-depth N` | Max call-follow depth (default: `5`) |
| `--stack-context N` | Show N qwords before/after RSP (default: `4`, `0` to hide) |
| `--realism-level {0,1,2}` | Environment realism: `0`=minimal, `1`=moderate, `2`=high |
| `--stack-size BYTES` | Stack size in bytes (default: 524288 = 512 KB) |
| `--repmax N` | Max REP iterations per step (default: `256`; `0`=unlimited) |
| `--crash-mode` | `rollback` / `partial` / `continue` (default: `rollback`) |
| `--json-output` | Emit a JSON summary after emulation |
| `--interactive` | Pause for input before each step |

---

## Realism Levels Explained

| Level | Stack | PEB/TEB | Heap | FS/GS |
|-------|-------|---------|------|-------|
| 0 – Minimal | zero-filled | none | none | not set |
| 1 – Moderate | randomised entropy | stubs (BeingDebugged=0, NtGlobalFlag=0) | none | GS→TEB |
| 2 – High | randomised entropy | full field population | 1 MB fake heap | GS→TEB |

Use level ≥1 to bypass common anti-emulation fingerprint checks (PEB.BeingDebugged, NtGlobalFlag, stack entropy checks).

---

## API Hooks

The following Windows API functions are stubbed by default:

| Category | Functions |
|----------|-----------|
| Memory | `VirtualAlloc`, `VirtualAllocEx`, `HeapAlloc`, `RtlAllocateHeap` |
| Library | `GetProcAddress`, `LoadLibraryA/W/ExA/ExW`, `GetModuleHandleA/W` |
| Protection | `VirtualProtect`, `VirtualProtectEx` |
| Query | `NtQuerySystemInformation`, `ZwQuerySystemInformation` |
| File I/O | `CreateFileA/W`, `ReadFile`, `WriteFile`, `CloseHandle` |
| Anti-debug | `IsDebuggerPresent` → 0, `CheckRemoteDebuggerPresent` → FALSE |
| Process | `ExitProcess` → cleanly stops emulation |

You can register custom hooks:

```python
from src.hooks import HookRegistry

registry = HookRegistry()

@registry.hook("MyCustomAPI")
def my_hook(emu, args):
    # args = (rcx, rdx, r8, r9)
    print(f"MyCustomAPI called: {args}")
    return 1   # return value in RAX
```

---

## Observer System

Attach callbacks to emulation events without touching core emulator logic:

```python
from src.session import EmulatorSession
from src.config  import EmulatorConfig
from src.observers import BaseObserver

class MyObserver(BaseObserver):
    def on_instruction(self, *, step, va, insn, emu, **kw):
        print(f"[{step}] 0x{va:x}: {insn}")

    def on_memory_write(self, *, va, data, emu, **kw):
        print(f"  write 0x{va:x} <- {data.hex()}")

    def on_exception(self, *, exc, va, emu, **kw):
        print(f"  !! {type(exc).__name__} at 0x{va:x}")

cfg  = EmulatorConfig(max_instructions=500, realism_level=1)
sess = EmulatorSession.from_shellcode(b"\x48\x31\xc0\xc3", cfg=cfg)
sess.set_observer(MyObserver())
sess.run()
print(sess.export_json())
```

### Available events

| Event constant | Kwargs |
|---------------|--------|
| `EVT_INSTRUCTION` | `step, va, insn, emu` |
| `EVT_MEM_WRITE` | `va, data, emu` |
| `EVT_MEM_READ` | `va, size, emu` |
| `EVT_EXCEPTION` | `exc, va, emu` |
| `EVT_CALL` | `from_va, target, depth, emu` |
| `EVT_RETURN` | `from_va, ret_va, depth, emu` |
| `EVT_HOOK_FIRED` | `hook_name, args, ret_val, emu` |
| `EVT_SESSION_START` | `va, config` |
| `EVT_SESSION_END` | `steps, va, config` |

---

## EmulatorSession API

```python
from src.session import EmulatorSession
from src.config  import EmulatorConfig

cfg  = EmulatorConfig(max_instructions=1000, realism_level=2)
sess = EmulatorSession.from_pe("malware.exe", 0x140001000, cfg)

# Step one instruction at a time
while sess.step():
    snap = sess.get_snapshot()   # dict with registers + memory writes

# Or run to completion
sess.reset()
sess.run()

# Run until a virtual address
sess.reset()
sess.run_until_va(0x14000110a)

# Run until a custom condition
sess.reset()
sess.run_until(lambda emu: emu.getRegisterByName("rax") == 0x1337)

# Export full state to JSON
print(sess.export_json())
```

---

## 🦾 Superpowered Agentic Development

`emulat3rai` is built specifically for **agentic, self-healing modularity**. Use the integrated architectural skill to guide AI agents through complex extensions:

### 🧩 Architectural Skill
- **Path**: [emulat3rai-architect](skills/emulat3rai-architect/SKILL.md)
- **Superpower**: Provides a "Master Protocol" for self-healing code migration and malware pattern integration.

### 🧪 Analyst Masterclass
- **Path**: [emulat3rai-analyst](skills/emulat3rai/SKILL.md)
- **Superpower**: Facilitates "Best Output" by providing strategic guidance on realism levels, recovery mechanisms, and skill synthesis.

---

## 🧠 Integrated Analysis Skills

Custom analysis engines and heuristics live in `src/skills/`.

### 🔍 AntiLoopholeDetector
- **Function**: Detects `REP`-prefixed instruction abuse and hot-address loops.
- **Safety**: Automatically aborts or warns when a suspicious loop threshold is exceeded.

### 🌳 DeepExploreObserver
- **Function**: Generates a high-fidelity call tree and logs every API hook interaction.
- **Output**: Visualizes execution flow for identifying packer unpacking routines.

### 🦠 MalwarePatternSkill
- **Function**: Pattern-based detection for Anti-Debug, Anti-VM, and Code Injection.
- **Signals**: Flags `IsDebuggerPresent`, `NtGlobalFlag`, and `PEB.BeingDebugged` lookups in the guest.

---

## How it works

The emulator is configured to match FLOSS internals:
- Configurable stack size (default 512 KB), optionally entropy-filled
- `rep` instructions capped at configurable iterations (default 256)
- Default vivisect API hooks removed for raw stepping
- All memory writes logged via vivisect's `writelog`

When `--follow-calls` is used, call instructions are executed manually (push return address, set PC to target). If a followed call crashes, the emulator rolls back to the pre-call state and lets vivisect handle it as a skip.

---

## Examples

```bash
$ python emulat3.py --sc-hex "48C7C00A00000048C7C3140000004801D8"
$ python emulat3.py --shellcode ./example/code.hex --hex
$ python emulat3.py --pe ./example/xor.exe --list
$ python emulat3.py --pe ./example/xor.exe --realism-level 2 --crash-mode continue --json-output
```
