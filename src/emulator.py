"""
Core emulator utilities for emulat3rai.

This module provides:
- make_emulator()   – low-level factory (backward compatible)
- step_emulator()   – classic stepping loop using the rich printer observer
- Format helpers    – format_registers, format_stack, format_flags, format_write, disasm

For the high-level session API see src/session.py.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

import envi
import envi.exc
import viv_utils
import viv_utils.emulator_drivers
from rich import print as rprint

from .consts import *
from .config import EmulatorConfig, CRASH_ROLLBACK, CRASH_PARTIAL, CRASH_CONTINUE
from .environment import setup_environment
from .analyzer import is_safe_to_follow
from .hooks import build_default_registry, StopEmulation
from .observers import (
    ObserverMixin,
    EVT_INSTRUCTION, EVT_MEM_WRITE, EVT_EXCEPTION,
    EVT_CALL, EVT_RETURN, EVT_HOOK_FIRED,
    EVT_SESSION_START, EVT_SESSION_END,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# make_emulator  (backward-compatible signature + new cfg path)
# ---------------------------------------------------------------------------

def make_emulator(vw: Any, cfg: Optional[EmulatorConfig] = None) -> Any:
    """
    Create and configure a vivisect emulator.

    If *cfg* is provided the environment is set up according to it
    (realism_level, stack_size, repmax, …).  Otherwise falls back to
    the original FLOSS-style defaults.
    """
    emu = vw.getEmulator(logwrite=True, taintbyte=b"\x00")

    if cfg is not None:
        viv_utils.emulator_drivers.remove_default_viv_hooks(emu)
        setup_environment(emu, cfg)
        return emu

    # --- legacy path (no cfg) ---
    memory_snap = emu.getMemorySnap()
    for i in range(len(memory_snap) - 1, -1, -1):
        _, _, info, _ = memory_snap[i]
        if info[3] == STACK_MEM_NAME:
            del memory_snap[i]
            emu.setMemorySnap(memory_snap)
            emu.stack_map_base = None
            break

    stack_size = int(0.5 * MEGABYTE)
    emu.initStackMemory(stacksize=stack_size)
    emu.writeMemory(emu.stack_map_base, b"\x00" * stack_size)
    emu.setStackCounter(emu.getStackCounter() - int(0.25 * MEGABYTE))
    emu.setEmuOpt("i386:repmax", 256)
    viv_utils.emulator_drivers.remove_default_viv_hooks(emu)
    return emu


# ---------------------------------------------------------------------------
# Disassembly / formatting helpers
# ---------------------------------------------------------------------------

def disasm(emu: Any, va: int) -> str:
    """Disassemble one instruction at *va*."""
    try:
        op = emu.parseOpcode(va)
        return str(op)
    except Exception as e:
        return f"<disasm error: {e}>"


def get_reg_names() -> list:
    return AMD64_REGS


def format_registers(emu: Any) -> str:
    """Format current register values into a readable block."""
    lines = []
    row = []
    for i, name in enumerate(AMD64_REGS):
        val = emu.getRegisterByName(name)
        row.append(f"{name:>4s}=0x{val:016x}")
        if len(row) == 4 or i == len(AMD64_REGS) - 1:
            lines.append("  ".join(row))
            row = []

    pc     = emu.getProgramCounter()
    eflags = emu.getRegisterByName("eflags")
    lines.append(f"  rip=0x{pc:016x}  eflags=0x{eflags:08x} [{format_flags(eflags)}]")
    return "\n".join(lines)


def format_flags(eflags: int) -> str:
    """Format EFLAGS register into readable flag names."""
    parts = []
    for bit, name in EFLAGS:
        if eflags & (1 << bit):
            parts.append(name)
    return " ".join(parts) if parts else "(none)"


def format_stack(emu: Any, context: int = 4) -> str:
    """Format stack around the current stack pointer."""
    sp     = emu.getStackCounter()
    lines  = []
    start  = sp - (context * 8)
    end    = sp + (context * 8)
    for addr in range(end, start - 8, -8):
        try:
            val    = emu.readMemoryFormat(addr, "<Q")[0]
            marker = " <-- RSP" if addr == sp else ""
            lines.append(f"  0x{addr:016x}: 0x{val:016x}{marker}")
        except Exception:
            marker = " <-- RSP" if addr == sp else ""
            lines.append(f"  0x{addr:016x}: ????????????????{marker}")
    return "\n".join(lines)


def format_write(va: int, data: bytes) -> str:
    """Format a single memory write entry for display."""
    ascii_repr = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in data)
    return f"  >> mem write: [0x{va:016x}] <- {data.hex()} \"{ascii_repr}\""


def do_call_manually(emu: Any, op: Any) -> bool:
    """
    Manually execute a call instruction by pushing the return address
    and setting PC to the target.
    Returns True if the call was followed, False otherwise.
    """
    try:
        target = op.getOperValue(0, emu)
    except Exception:
        return False

    if target is None or target == 0:
        return False

    try:
        emu.parseOpcode(target)
    except Exception:
        return False

    ret_addr = op.va + len(op)
    sp = emu.getStackCounter()
    sp -= 8
    emu.setStackCounter(sp)
    emu.writeMemory(sp, ret_addr.to_bytes(8, "little"))
    emu.setProgramCounter(target)
    return True


# ---------------------------------------------------------------------------
# Rich-printer observer (used by step_emulator)
# ---------------------------------------------------------------------------

class _RichPrinterObserver:
    """Internal observer that reproduces the original rich-based output."""

    def __init__(self, stack_context: int = STACK_CTX) -> None:
        self.stack_context  = stack_context
        self._prev_wlog_len = 0
        self._baseline      = 0

    def set_baseline(self, length: int) -> None:
        self._baseline      = length
        self._prev_wlog_len = length

    def on_step(self, step: int, pc: int, insn: str, emu: Any) -> None:
        rprint(f"\nStep [yellow]{step:>4d}[/yellow] | "
               f"[magenta]0x{pc:016x}[/magenta]: [cyan]{insn}[/cyan]")
        rprint(f"{'-' * 78}")
        rprint(format_registers(emu))
        if self.stack_context > 0:
            rprint(f"\n  Stack:")
            rprint(format_stack(emu, self.stack_context))

    def on_writes(self, emu: Any) -> None:
        wlog = emu.getPathProp("writelog")
        if len(wlog) > self._prev_wlog_len:
            for _, va, data in wlog[self._prev_wlog_len:]:
                rprint(format_write(va, data))
            self._prev_wlog_len = len(wlog)

    def on_exception(self, exc: Exception, pc: int, emu: Any) -> None:
        if isinstance(exc, envi.SegmentationViolation):
            rprint(f"  !! SEGFAULT at 0x{pc:x}: {exc}")
            rprint(f"     (memory access to unmapped region)")
            rprint(f"\n  Registers at crash:")
            rprint(format_registers(emu))
        elif isinstance(exc, envi.exc.BreakpointHit):
            rprint(f"  !! BREAKPOINT: {exc}")
        elif isinstance(exc, envi.InvalidInstruction):
            rprint(f"  !! INVALID INSTRUCTION at 0x{pc:x}: {exc}")
        else:
            rprint(f"  !! EXCEPTION at 0x{pc:x}: {type(exc).__name__}: {exc}")

    def final_summary(self, step: int, emu: Any, baseline: int) -> None:
        rprint(f"\n{'=' * 78}")
        rprint(f"\n[[green]*[/green]] Final state after [green]{step}[/green] steps:")
        rprint(format_registers(emu))

        sp = emu.getStackCounter()
        rprint(f"\n[[magenta]*[/magenta]] Stack around SP [yellow](0x{sp:x})[/yellow]:")
        for offset in range(0x30, -0x18, -8):
            addr = sp - offset
            try:
                val    = emu.readMemoryFormat(addr, "<Q")[0]
                marker = " <-- SP" if addr == sp else ""
                rprint(f"  0x{addr:016x}: 0x{val:016x}{marker}")
            except Exception:
                pass

        wlog       = emu.getPathProp("writelog")
        user_writes = wlog[baseline:]
        if user_writes:
            rprint(f"\n[[red]*[/red]] Memory writes during emulation ({len(user_writes)} total):")
            for _, va, data in user_writes:
                ascii_repr = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in data)
                rprint(f"  [0x{va:016x}] <- {data.hex():20s} \"{ascii_repr}\"")

        rprint(f"\n[[green]*[/green]] Done.")


# ---------------------------------------------------------------------------
# step_emulator  (classic entry-point, now delegates to EmulatorSession)
# ---------------------------------------------------------------------------

def step_emulator(
    emu: Any,
    start_va: int,
    max_instructions: int = MAX_INST_SIZE,
    stop_on_ret: bool = True,
    follow_calls: bool = False,
    follow_va: Optional[int] = None,
    vw: Any = None,
    stack_context: int = STACK_CTX,
    cfg: Optional[EmulatorConfig] = None,
) -> int:
    """
    Step through instructions one at a time from *start_va*.

    This function is the original API; it delegates to EmulatorSession
    internally so all new features (observers, crash modes, hooks) are
    available, while the output format is unchanged.
    """
    from .session import EmulatorSession
    from .hooks import build_default_registry

    # Build a compatible config
    if cfg is None:
        cfg = EmulatorConfig(
            max_instructions=max_instructions,
            follow_calls=follow_calls,
            follow_va=follow_va,
            stack_context=stack_context,
            stop_on_ret=stop_on_ret,
        )

    printer = _RichPrinterObserver(stack_context=stack_context)

    # If no workspace provided, create a minimal session without one
    if vw is None:
        return _step_emulator_legacy(emu, start_va, max_instructions,
                                     stop_on_ret, printer)

    # --- build session around the already-prepared emulator ---
    sess = EmulatorSession(
        vw=vw,
        emu=emu,
        start_va=start_va,
        cfg=cfg,
        hook_registry=build_default_registry(),
    )

    baseline = sess._baseline_wlog_len
    printer.set_baseline(baseline)

    emu.setProgramCounter(start_va)

    rprint(f"\n[[green]*[/green]] Initial state:")
    rprint(format_registers(emu))
    if stack_context > 0:
        rprint(f"\n  Stack:")
        rprint(format_stack(emu, stack_context))
    rprint(f"\n{'=' * 78}")

    step = 0
    while step < max_instructions:
        pc = emu.getProgramCounter()
        step += 1

        insn_str = disasm(emu, pc)
        printer.on_step(step, pc, insn_str, emu)

        try:
            op = emu.parseOpcode(pc)
        except Exception:
            op = None

        hook_fired = False
        followed   = False

        if op is not None and op.mnem == "call":
            target = None
            try:
                target = op.getOperValue(0, emu)
            except Exception:
                pass

            if target is not None:
                name = sess._resolve_import_name(target)
                if name:
                    def _emit_hook(hook_name, args, ret_val, emu, **kw):
                        rprint(f"  >> hooked: {hook_name}() -> 0x{ret_val:x}" if isinstance(ret_val, int) else f"  >> hooked: {hook_name}()")
                    fired = sess.hooks.maybe_fire(name, emu, emit_fn=_emit_hook)
                    if fired:
                        emu.setProgramCounter(pc + len(op))
                        rprint(format_registers(emu))
                        printer.on_writes(emu)
                        hook_fired = True

            if not hook_fired and op is not None and op.mnem == "call":
                if (cfg.follow_calls or cfg.follow_va is not None) and vw is not None:
                    depth_ok = sess._call_depth < max(cfg.follow_depth, 1)
                    if depth_ok:
                        should_follow = False
                        if cfg.follow_va is not None:
                            should_follow = (target == cfg.follow_va)
                        else:
                            should_follow = is_safe_to_follow(vw, emu, op)

                        if should_follow and target is not None:
                            sess._snap          = emu.getEmuSnap()
                            sess._snap_wlog_len = len(emu.getPathProp("writelog"))
                            printer._prev_wlog_len = sess._snap_wlog_len
                            if do_call_manually(emu, op):
                                sess._call_depth += 1
                                rprint(f"  >> following call to 0x{target:x}")
                                rprint(format_registers(emu))
                                printer.on_writes(emu)
                                followed = True

        if op is not None and op.mnem.startswith("ret") and sess._call_depth > 0:
            sess._call_depth -= 1

        if hook_fired or followed:
            continue

        # execute
        try:
            emu.stepi()
        except StopEmulation as e:
            rprint(f"  !! ExitProcess called ({e.exit_code}), stopping")
            break
        except (envi.exc.BreakpointHit,
                envi.InvalidInstruction,
                envi.SegmentationViolation,
                Exception) as exc:
            
            # --- Advanced Recovery Logic ---
            recovery_mode = cfg.crash_recovery
            
            if recovery_mode == "rollback":
                if sess.rollback():
                    rprint(f"  !! Crash ({type(exc).__name__}) - Rolling back to previous checkpoint")
                    continue
                else:
                    rprint(f"  !! Crash ({type(exc).__name__}) - No checkpoints available for rollback")
            
            elif recovery_mode == "partial":
                if op is not None:
                    # NOP-patching: Write 0x90 over the failing instruction and skip it
                    try:
                        emu.writeMemory(pc, b"\x90" * len(op))
                        emu.setProgramCounter(pc + len(op))
                        rprint(f"  !! Crash ({type(exc).__name__}) - NOP-patching instruction at 0x{pc:x} and resuming")
                        continue
                    except Exception as e2:
                        rprint(f"  !! Failed to NOP-patch at 0x{pc:x}: {e2}")
                else:
                    rprint(f"  !! Crash ({type(exc).__name__}) - Cannot NOP-patch (opcode unknown)")

            # Fallback legacy behavior for calls (if no advanced recovery or failed)
            if sess._call_depth > 0 and sess._snap is not None:
                emu.setEmuSnap(sess._snap)
                printer._prev_wlog_len = sess._snap_wlog_len
                sess._call_depth = 0
                sess._snap       = None
                rprint(f"  !! call crashed ({type(exc).__name__}), rolling back and skipping")
                try:
                    emu.stepi()
                except Exception:
                    pass
                rprint(format_registers(emu))
                printer.on_writes(emu)
                continue

            printer.on_exception(exc, pc, emu)
            break

        printer.on_writes(emu)

        if stop_on_ret and insn_str.strip().startswith("ret") and sess._call_depth == 0:
            rprint(f"\n[*] Function returned after {step} steps")
            break

        new_pc = emu.getProgramCounter()
        if new_pc == 0:
            rprint(f"\n[*] PC reached 0x0 after {step} steps (likely end of shellcode)")
            break

    printer.final_summary(step, emu, baseline)
    return step


def _step_emulator_legacy(emu, start_va, max_instructions, stop_on_ret, printer):
    """Fallback when no workspace is available (shellcode without vw)."""
    emu.setProgramCounter(start_va)
    baseline = len(emu.getPathProp("writelog"))
    printer.set_baseline(baseline)

    rprint(f"\n[[green]*[/green]] Initial state:")
    rprint(format_registers(emu))
    rprint(f"\n{'=' * 78}")

    step = 0
    while step < max_instructions:
        pc   = emu.getProgramCounter()
        step += 1
        insn_str = disasm(emu, pc)
        printer.on_step(step, pc, insn_str, emu)

        try:
            emu.stepi()
        except StopEmulation as e:
            rprint(f"  !! ExitProcess({e.exit_code}), stopping")
            break
        except (envi.exc.BreakpointHit, envi.InvalidInstruction,
                envi.SegmentationViolation, Exception) as exc:
            printer.on_exception(exc, pc, emu)
            break

        printer.on_writes(emu)

        if stop_on_ret and insn_str.strip().startswith("ret"):
            rprint(f"\n[*] Function returned after {step} steps")
            break

        if emu.getProgramCounter() == 0:
            rprint(f"\n[*] PC reached 0x0 after {step} steps")
            break

    printer.final_summary(step, emu, baseline)
    return step
