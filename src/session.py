"""
EmulatorSession – high-level, agent-friendly emulation API.

This class wraps the low-level vivisect emulator and exposes a clean
interface suitable for step-by-step analysis, observers, and AI agents.

Quick usage::

    from src.session import EmulatorSession
    from src.config import EmulatorConfig

    cfg   = EmulatorConfig(max_instructions=500, realism_level=1)
    sess  = EmulatorSession.from_pe("malware.exe", 0x140001000, cfg)
    sess.set_observer(MyObserver())
    sess.run()
    print(sess.export_json())
"""
from __future__ import annotations

import json
import logging
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

from .consts import STACK_MEM_NAME, AMD64_REGS

import envi
import envi.exc
import viv_utils
import viv_utils.emulator_drivers

from .config import (
    EmulatorConfig,
    CRASH_ROLLBACK, CRASH_PARTIAL, CRASH_CONTINUE,
)
from .consts import STACK_MEM_NAME
from .hooks import HookRegistry, build_default_registry, StopEmulation
from .observers import (
    ObserverMixin, BaseObserver,
    EVT_INSTRUCTION, EVT_MEM_WRITE, EVT_MEM_READ,
    EVT_EXCEPTION, EVT_CALL, EVT_RETURN,
    EVT_HOOK_FIRED, EVT_SESSION_START, EVT_SESSION_END,
)
from .environment import setup_environment
from .analyzer import is_safe_to_follow

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Low-level emulator factory (mirrors old make_emulator, but uses cfg)
# ---------------------------------------------------------------------------

def _make_raw_emulator(vw: Any, cfg: EmulatorConfig) -> Any:
    """Create a vivisect emulator without extra setup (setup_environment does the rest)."""
    emu = vw.getEmulator(logwrite=True, taintbyte=b"\x00")
    # Remove the default [stack] – environment.setup_stack will rebuild it
    memory_snap = emu.getMemorySnap()
    for i in range(len(memory_snap) - 1, -1, -1):
        _, _, info, _ = memory_snap[i]
        if info[3] == STACK_MEM_NAME:
            del memory_snap[i]
            emu.setMemorySnap(memory_snap)
            emu.stack_map_base = None
            break
    viv_utils.emulator_drivers.remove_default_viv_hooks(emu)
    return emu


# ---------------------------------------------------------------------------
# EmulatorSession
# ---------------------------------------------------------------------------

class EmulatorSession(ObserverMixin):
    """
    High-level emulation session with observer support, hook registry,
    and JSON-serialisable state snapshots.
    """

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(self,
                 vw: Any,
                 emu: Any,
                 start_va: int,
                 cfg: Optional[EmulatorConfig] = None,
                 hook_registry: Optional[HookRegistry] = None) -> None:
        super().__init__()
        self.vw          = vw
        self.emu         = emu
        self.start_va    = start_va
        self.cfg         = cfg or EmulatorConfig()
        self.hooks       = hook_registry or build_default_registry()
        self.env         = None # populated in factory or manually

        self._step_count  = 0
        self._call_depth  = 0
        self._call_stack: List[Tuple[int, int]] = []   # [(from_va, target_va), ...]
        self._snap: Optional[Any]  = None              # pre-call snapshot
        self._snap_wlog_len: int   = 0
        self._finished    = False
        self._events: List[Dict]   = []                # for export_json

        # writelog baseline (skip emulator-init writes)
        self._baseline_wlog_len = len(emu.getPathProp("writelog"))
        self._prev_wlog_len     = self._baseline_wlog_len

        # Thread safety lock
        self._lock = threading.Lock()
        
        # Checkpoint stack for rollbacks
        self._checkpoints: List[Tuple[Dict[str, int], bytes]] = [] # [(regs, mem_snap), ...]

    # ------------------------------------------------------------------
    # Class-method constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_pe(cls, pe_path: str, function_va: Optional[int],
                cfg: Optional[EmulatorConfig] = None,
                hook_registry: Optional[HookRegistry] = None) -> "EmulatorSession":
        import os
        from .misc import suppress_viv_logging
        suppress_viv_logging()
        vw = viv_utils.getWorkspace(pe_path)
        if function_va is None:
            function_va = vw.getEntryPoints()[0]
        cfg = cfg or EmulatorConfig()
        emu = _make_raw_emulator(vw, cfg)
        from .environment import EnvironmentManager
        mgr = EnvironmentManager(emu, cfg)
        mgr.setup()
        sess = cls(vw, emu, function_va, cfg, hook_registry)
        sess.env = mgr
        return sess

    @classmethod
    def from_shellcode(cls, sc_bytes: bytes,
                       cfg: Optional[EmulatorConfig] = None,
                       hook_registry: Optional[HookRegistry] = None) -> "EmulatorSession":
        """Build an EmulatorSession from raw shellcode bytes."""
        from .misc import suppress_viv_logging
        suppress_viv_logging()
        cfg = cfg or EmulatorConfig()
        vw = viv_utils.getShellcodeWorkspace(
            sc_bytes, "amd64",
            base=cfg.sc_base,
            entry_point=cfg.sc_entry_offset,
        )
        emu = _make_raw_emulator(vw, cfg)
        from .environment import EnvironmentManager
        mgr = EnvironmentManager(emu, cfg)
        mgr.setup()
        start_va = cfg.sc_base + cfg.sc_entry_offset
        sess = cls(vw, emu, start_va, cfg, hook_registry)
        sess.env = mgr
        return sess

    # ------------------------------------------------------------------
    # Observer helpers (proxies to ObserverMixin)
    # ------------------------------------------------------------------


    # ------------------------------------------------------------------
    # Snapshot Management
    # ------------------------------------------------------------------

    def take_snapshot(self) -> None:
        """Take a full state snapshot of the current emulator state."""
        with self._lock:
            self._snap = self.emu.getEmuSnap()
            self._snap_wlog_len = len(self.emu.getPathProp("writelog"))

    def restore_snapshot(self, memory: bool = True) -> None:
        """Restore the emulator to the last captured snapshot."""
        with self._lock:
            if self._snap is None:
                return
            
            if memory:
                # Full restore (Registers + Memory)
                self.emu.setEmuSnap(self._snap)
                self._prev_wlog_len = self._snap_wlog_len
            else:
                # Partial restore (Registers only)
                regs = self._snap.get('regs', [])
                for reg_idx, val in enumerate(regs):
                    self.emu.setRegister(reg_idx, val)


    def to_dict(self) -> Dict[str, Any]:
        """
        Hybrid Serialization: All metadata + Raw bytes for high-value regions.
        """
        with self._lock:
            # 1. Registers
            regs: Dict[str, int] = {}
            for name in self.emu.getRegisterNames():
                try: regs[name] = self.emu.getRegisterByName(name)
                except: regs[name] = 0

            # 2. Memory Maps (Hybrid)
            maps = []
            high_value_bases = []
            if self.env:
                high_value_bases = [
                    self.env.stack_base, self.env.heap_base,
                    self.env.peb_base, self.env.teb_base
                ]
            
            for va, size, perm, name in self.emu.getMemoryMaps():
                m_info = {
                    "va": f"0x{va:0x}",
                    "size": size,
                    "perm": perm,
                    "name": name,
                    "data": None
                }
                # Include raw bytes if it's a high-value region
                if va in high_value_bases:
                    try:
                        m_info["data"] = self.emu.readMemory(va, size).hex()
                    except: pass
                maps.append(m_info)

            return {
                "arch": self._arch,
                "start_va": f"0x{self.start_va:0x}",
                "pc": f"0x{self.emu.getProgramCounter():0x}",
                "registers": {k: f"0x{v:0x}" for k, v in regs.items()},
                "config": self.cfg.to_dict(),
                "memory_maps": maps,
                "step_count": self._step_count,
                "finished": self._finished
            }

    # ------------------------------------------------------------------
    # Checkpoints & Rollback (Advanced Recovery)
    # ------------------------------------------------------------------

    def checkpoint(self) -> None:
        """Save a recovery point (Registers + Memory)."""
        with self._lock:
            regs = {n: self.emu.getRegisterByName(n) for n in self.emu.getRegisterNames()}
            snap = self.emu.getMemorySnap()
            self._checkpoints.append((regs, snap))
            logger.debug("Checkpoint created at 0x%x", self.emu.getProgramCounter())

    def rollback(self) -> bool:
        """Revert to the last checkpoint. Returns True on success."""
        with self._lock:
            if not self._checkpoints:
                return False
            regs, snap = self._checkpoints.pop()
            self.emu.setMemorySnap(snap)
            for name, val in regs.items():
                self.emu.setRegisterByName(name, val)
            logger.info("Rolled back to previous state. New PC: 0x%x", self.emu.getProgramCounter())
            return True

    def export_json(self) -> str:
        """Helper for agentic consumption."""
        return json.dumps({
            "session_info": self.to_dict(),
            "events": self._events
        }, indent=2)

    # ------------------------------------------------------------------
    # Stepping API
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Reset the PC to start_va without rebuilding the emulator."""
        self.emu.setProgramCounter(self.start_va)
        self._step_count  = 0
        self._call_depth  = 0
        self._call_stack  = []
        self._snap        = None
        self._finished    = False
        self._events      = []
        self._baseline_wlog_len = len(self.emu.getPathProp("writelog"))
        self._prev_wlog_len     = self._baseline_wlog_len

    def step(self) -> bool:
        """
        Execute one instruction with thread-safety and internal locking.
        Returns True if stepping should continue, False if it should stop.
        """
        with self._lock:
            if self._finished:
                return False

        if self._step_count == 0:
            self.emu.setProgramCounter(self.start_va)
            self.emit(EVT_SESSION_START,
                      va=self.start_va, config=self.cfg)

        pc = self.emu.getProgramCounter()
        self._step_count += 1

        # --- disassemble ---
        try:
            op = self.emu.parseOpcode(pc)
            insn_str = str(op)
        except Exception as e:
            insn_str = f"<parse error: {e}>"
            op = None

        self.emit(EVT_INSTRUCTION,
                  step=self._step_count, va=pc, insn=insn_str, emu=self.emu)
        self._log_event("instruction",
                        step=self._step_count, va=pc, insn=insn_str)

        # --- call/ret tracking + hook intercept ---
        if op is not None:
            stop = self._handle_call_ret(op, pc, insn_str)
            if stop is not None:          # None = "continue normally"
                return stop

        # --- execute ---
        continued = self._execute_step(pc, op, insn_str)
        if not continued:
            return False

        # --- new memory writes ---
        self._drain_writelog()

        # --- stop conditions ---
        if self.cfg.stop_on_ret and op is not None:
            mnem = getattr(op, "mnem", "") or ""
            if mnem.startswith("ret") and self._call_depth == 0:
                self._finish()
                return False

        new_pc = self.emu.getProgramCounter()
        if new_pc == 0:
            self._finish()
            return False

        return True

    def run(self) -> int:
        """Run until max_instructions, ret, or exception.  Returns step count."""
        self.emu.setProgramCounter(self.start_va)
        while self._step_count < self.cfg.max_instructions:
            if not self.step():
                break
        else:
            self._finish()
        return self._step_count

    def run_until(self, predicate: Callable[[Any], bool]) -> int:
        """Run until *predicate(emu)* returns True.  Returns step count."""
        self.emu.setProgramCounter(self.start_va)
        while self._step_count < self.cfg.max_instructions:
            if predicate(self.emu):
                break
            if not self.step():
                break
        return self._step_count

    def run_until_va(self, target_va: int) -> int:
        """Run until the PC reaches *target_va*.  Returns step count."""
        return self.run_until(lambda emu: emu.getProgramCounter() == target_va)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _handle_call_ret(self, op: Any, pc: int,
                         insn_str: str) -> Optional[bool]:
        """
        Handle call/ret depth tracking and optional call following.

        Returns:
          True  – continue stepping (we manually set PC, skip stepi)
          False – stop stepping
          None  – let the normal stepi path handle it
        """
        mnem: str = getattr(op, "mnem", "") or ""
        cfg = self.cfg

        if mnem == "call":
            try:
                target = op.getOperValue(0, self.emu)
            except Exception:
                target = None

            # --- API hook intercept (before following) ---
            if target is not None:
                hook_name = self._resolve_import_name(target)
                if hook_name:
                    fired = self.hooks.maybe_fire(
                        hook_name, self.emu,
                        emit_fn=lambda **kw: self.emit(EVT_HOOK_FIRED, **kw),
                    )
                    if fired:
                        # advance PC past the call
                        self.emu.setProgramCounter(pc + len(op))
                        return True   # continue

            # --- call following ---
            should_follow = False
            if (target is not None
                    and (cfg.follow_calls or cfg.follow_va is not None)
                    and self._call_depth < max(cfg.follow_depth, 1)):
                if cfg.follow_va is not None:
                    should_follow = (target == cfg.follow_va)
                else:
                    should_follow = is_safe_to_follow(self.vw, self.emu, op)

            if should_follow and target is not None:
                self._snap         = self.emu.getEmuSnap()
                self._snap_wlog_len = len(self.emu.getPathProp("writelog"))
                if self._do_call_manually(op):
                    self._call_stack.append((pc, target))
                    self._call_depth += 1
                    self.emit(EVT_CALL, from_va=pc, target=target,
                              depth=self._call_depth, emu=self.emu)
                    return True   # skip stepi; PC is already set

        elif mnem.startswith("ret") and self._call_depth > 0:
            ret_va = self.emu.getProgramCounter()
            self._call_depth -= 1
            if self._call_stack:
                from_va, _target = self._call_stack.pop()
            else:
                from_va = pc
            self.emit(EVT_RETURN, from_va=from_va, ret_va=ret_va,
                      depth=self._call_depth, emu=self.emu)

        return None   # no special handling needed

    def _execute_step(self, pc: int, op: Any,
                      insn_str: str) -> bool:
        """stepi() with exception handling.  Returns True to continue."""
        try:
            self.emu.stepi()
        except StopEmulation as e:
            # ExitProcess is a normal termination, not an error condition
            self._log_event("exit_process", va=pc, exit_code=e.exit_code)
            self._finish()
            return False
        except (envi.exc.BreakpointHit,
                envi.InvalidInstruction,
                envi.SegmentationViolation,
                Exception) as exc:
            self.emit(EVT_EXCEPTION, exc=exc, va=pc, emu=self.emu)
            self._log_event("exception", va=pc,
                            exc_type=type(exc).__name__, exc_msg=str(exc))

            # --- crash recovery ---
            mode = self.cfg.crash_mode

            if self._call_depth > 0 and self._snap is not None:
                # Always roll back when inside a followed call
                self.emu.setEmuSnap(self._snap)
                self._prev_wlog_len = self._snap_wlog_len
                self._call_depth    = 0
                self._call_stack    = []
                self._snap          = None
                # re-execute with stepi (skip the call)
                try:
                    self.emu.stepi()
                except Exception:
                    pass
                return True

            if mode == CRASH_ROLLBACK:
                self._finish()
                return False
            elif mode == CRASH_PARTIAL:
                # restore registers only, keep memory writes (best-effort)
                self.restore_snapshot(memory=False)
                # skip the faulting instruction
                self.emu.setProgramCounter(pc + (len(op) if op else 1))
                return True
            else:  # CRASH_CONTINUE
                # skip the faulting instruction and keep going
                self.emu.setProgramCounter(pc + (len(op) if op else 1))
                return True

        return True

    def _do_call_manually(self, op: Any) -> bool:
        """Push return address, set PC to target.  Returns True on success."""
        try:
            target = op.getOperValue(0, self.emu)
        except Exception:
            return False
        if target is None or target == 0:
            return False
        try:
            self.emu.parseOpcode(target)
        except Exception:
            return False

        ret_addr = op.va + len(op)
        sp = self.emu.getStackCounter()
        sp -= 8
        self.emu.setStackCounter(sp)
        self.emu.writeMemory(sp, ret_addr.to_bytes(8, "little"))
        self.emu.setProgramCounter(target)
        return True

    def _drain_writelog(self) -> None:
        wlog = self.emu.getPathProp("writelog")
        if len(wlog) > self._prev_wlog_len:
            for _, va, data in wlog[self._prev_wlog_len:]:
                self.emit(EVT_MEM_WRITE, va=va, data=data, emu=self.emu)
                self._log_event("mem_write", va=va, data=data.hex())
            self._prev_wlog_len = len(wlog)

    def _resolve_import_name(self, va: int) -> Optional[str]:
        """Return the bare import name for *va* if it's in the IAT, else None."""
        try:
            name: str = self.vw.getName(va) or ""
            if not name:
                return None
            # vivisect format: "kernel32.GetProcAddress_<va>" or "GetProcAddress"
            if "." in name:
                name = name.split(".")[-1]
            suffix = f"_{va:x}"
            if name.endswith(suffix):
                name = name[: -len(suffix)]
            return name if name else None
        except Exception:
            return None

    def _finish(self) -> None:
        if not self._finished:
            self._finished = True
            self.emit(EVT_SESSION_END,
                      steps=self._step_count,
                      va=self.start_va,
                      config=self.cfg)

    def _log_event(self, kind: str, **kwargs) -> None:
        """Append a dict to the internal event log (for export_json)."""
        entry = {"kind": kind, "step": self._step_count}
        for k, v in kwargs.items():
            if isinstance(v, int):
                entry[k] = f"0x{v:x}"
            elif isinstance(v, bytes):
                entry[k] = v.hex()
            else:
                entry[k] = v
        self._events.append(entry)


# ---------------------------------------------------------------------------
# Standalone helper: dump emulator state to JSON without a full session
# ---------------------------------------------------------------------------

def emu_state_to_json(emu: Any, start_va: int, steps: int,
                      cfg: Optional[EmulatorConfig] = None,
                      baseline_wlog_len: int = 0,
                      indent: int = 2) -> str:
    """
    Return a JSON string describing the current emulator state.
    Useful when emulation was done via step_emulator() rather than EmulatorSession.
    *baseline_wlog_len* should be the writelog length captured before stepping began,
    so that stack-init writes are excluded from the output.
    """
    cfg = cfg or EmulatorConfig()

    regs: Dict[str, str] = {}
    for name in AMD64_REGS:
        try:
            regs[name] = f"0x{emu.getRegisterByName(name):016x}"
        except Exception:
            regs[name] = "0x????????????????"
    regs["rip"]    = f"0x{emu.getProgramCounter():016x}"
    regs["eflags"] = f"0x{emu.getRegisterByName('eflags'):08x}"

    wlog = emu.getPathProp("writelog")
    user_writes = wlog[baseline_wlog_len:]
    writes = [
        {"va": f"0x{va:016x}", "data": data.hex()}
        for _, va, data in user_writes
    ]

    return json.dumps({
        "start_va": f"0x{start_va:016x}",
        "steps":    steps,
        "config": {
            "max_instructions": cfg.max_instructions,
            "realism_level":    cfg.realism_level,
            "crash_mode":       cfg.crash_mode,
            "repmax":           cfg.repmax,
            "stack_size":       cfg.stack_size,
        },
        "final_state": {
            "step":          steps,
            "va":            f"0x{emu.getProgramCounter():016x}",
            "registers":     regs,
            "memory_writes": writes,
        },
    }, indent=indent)
