"""
API hooks registry for emulat3rai.

Hooks intercept calls to well-known Windows API functions.
Modern implementation uses decorators and handles x86/x64 calling conventions.
"""
from __future__ import annotations

import struct
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Hook function signature: hook(emu, args: tuple) -> int (return value for RAX)
HookFn = Callable[[Any, Tuple[int, ...]], int]

# Global registry populated by the @hook decorator
_GLOBAL_HOOKS: Dict[str, HookFn] = {}

def hook(name: str) -> Callable[[HookFn], HookFn]:
    """Decorator: @hook('VirtualAlloc')"""
    def decorator(fn: HookFn) -> HookFn:
        _GLOBAL_HOOKS[name] = fn
        return fn
    return decorator

# ---------------------------------------------------------------------------
# HookManager
# ---------------------------------------------------------------------------
class HookManager:
    """
    Manages the dispatching of hooks and argument extraction.
    """
    def __init__(self, emu: Any):
        self.emu = emu
        meta = emu.getMeta('Architecture') if hasattr(emu, 'getMeta') else {}
        # Handle case where getMeta might return bytes or other types
        if isinstance(meta, bytes):
            self._arch = meta.decode('utf-8', errors='ignore')
        elif isinstance(meta, str):
            self._arch = meta
        else:
            self._arch = 'unknown'  # 'amd64' or 'i386'
        self._hooks = _GLOBAL_HOOKS.copy()

    def register(self, name: str, fn: HookFn) -> None:
        """Override or add a manual hook."""
        self._hooks[name] = fn

    def maybe_fire(self, name: str, emit_fn: Optional[Callable] = None) -> bool:
        """
        Dispatches the hook if it exists. Returns True if handled.
        """
        fn = self._hooks.get(name)
        if not fn:
            return False

        # 1. Extract arguments based on Architecture
        args = self._get_args(4) # Standard Windows API hooks usually care about 4-6 args max

        # 2. Fire the hook
        try:
            ret_val = fn(self.emu, args)
        except StopEmulation:
            # Re-raise without logging as error; this is a controlled exit
            raise
        except Exception as exc:
            logger.error("Hook %s failed: %s", name, exc)
            ret_val = 0

        # 3. Set return value (RAX/EAX)
        reg = "rax" if self._arch == "amd64" else "eax"
        mask = 0xFFFFFFFFFFFFFFFF if self._arch == "amd64" else 0xFFFFFFFF
        try:
            self.emu.setRegisterByName(reg, ret_val & mask)
        except Exception:
            pass

        # 4. Log event
        if emit_fn:
            emit_fn(hook_name=name, args=args, ret_val=ret_val, emu=self.emu)

        return True

    def _get_args(self, count: int) -> Tuple[int, ...]:
        """Extracts 'count' arguments from the emulator's state."""
        if self._arch == "amd64":
            return self._get_args_x64(count)
        else:
            return self._get_args_x86(count)

    def _get_args_x64(self, count: int) -> Tuple[int, ...]:
        """Windows x64 FastCall: RCX, RDX, R8, R9, then stack."""
        regs = ["rcx", "rdx", "r8", "r9"]
        args: List[int] = []
        
        # FastCall registers
        for i in range(min(count, 4)):
            try:
                args.append(self.emu.getRegisterByName(regs[i]))
            except:
                args.append(0)
        
        # Overflow into stack (shadow space starts at [RSP + 8] for the 4 regs, then args)
        if count > 4:
            sp = self.emu.getStackCounter()
            for i in range(4, count):
                off = 8 + (i * 8) # skip return address and register shadow
                try:
                    val = struct.unpack("<Q", self.emu.readMemory(sp + off, 8))[0]
                    args.append(val)
                except:
                    args.append(0)
        
        return tuple(args)

    def _get_args_x86(self, count: int) -> Tuple[int, ...]:
        """Windows x86 StdCall: Arguments on stack pushed right-to-left."""
        sp = self.emu.getStackCounter()
        args: List[int] = []
        for i in range(count):
            off = 4 + (i * 4) # skip return address
            try:
                val = struct.unpack("<I", self.emu.readMemory(sp + off, 4))[0]
                args.append(val)
            except:
                args.append(0)
        return tuple(args)

# ---------------------------------------------------------------------------
# Default Hooks (Refactored)
# ---------------------------------------------------------------------------

_FAKE_HANDLE_BASE = 0x4000
_fake_handle_counter = _FAKE_HANDLE_BASE

def _next_handle() -> int:
    global _fake_handle_counter
    _fake_handle_counter += 4
    return _fake_handle_counter

def _emu_alloc(emu: Any, size: int, perms: int = 7) -> int:
    size = max(size, 0x1000)
    size = (size + 0xFFF) & ~0xFFF
    base = 0x10000000
    try:
        maps = [m[0] for m in emu.getMemoryMaps()]
        if maps: base = (max(maps) + 0x10000) & ~0xFFFF
    except: pass
    
    try:
        emu.addMemoryMap(base, perms, "heap_alloc", b"\x00" * size)
        return base
    except:
        return 0

# --- Implementation ---

@hook("VirtualAlloc")
@hook("VirtualAllocEx")
def h_virtual_alloc(emu: Any, args: Tuple[int, ...]) -> int:
    # VirtualAlloc(lpAddress, dwSize, ...)
    # x64: lpAddress=rcx, dwSize=rdx
    # x86: lpAddress=[esp+4], dwSize=[esp+8]
    # _get_args(4) returns (arg1, arg2, arg3, arg4)
    dw_size = args[1]
    return _emu_alloc(emu, dw_size if dw_size > 0 else 0x1000)

@hook("HeapAlloc")
@hook("RtlAllocateHeap")
def h_heap_alloc(emu: Any, args: Tuple[int, ...]) -> int:
    dw_bytes = args[2] # 3rd arg
    return _emu_alloc(emu, dw_bytes if dw_bytes > 0 else 0x100)

@hook("GetProcAddress")
@hook("LoadLibraryA")
@hook("LoadLibraryW")
@hook("GetModuleHandleA")
@hook("GetModuleHandleW")
def h_generic_handle(emu: Any, args: Tuple[int, ...]) -> int:
    return _next_handle()

@hook("IsDebuggerPresent")
def h_anti_debug(emu: Any, args: Tuple[int, ...]) -> int:
    return 0

@hook("ExitProcess")
def h_exit_process(emu: Any, args: Tuple[int, ...]) -> int:
    raise StopEmulation(args[0])

class StopEmulation(Exception):
    """Raised to signal clean termination of the emulation."""
    def __init__(self, exit_code: int = 0):
        super().__init__(f"Emulator exited with code: {exit_code}")
        self.exit_code = exit_code

# ---------------------------------------------------------------------------
# Compatibility Shim
# ---------------------------------------------------------------------------
class HookRegistry:
    """Manages a collection of hooks and provides a decorator-based API."""
    def __init__(self):
        self._manual: Dict[str, HookFn] = {}
        self._mgr: Optional[HookManager] = None
    
    def hook(self, name: str) -> Callable[[HookFn], HookFn]:
        """Decorator for local registry: @registry.hook('Library.Func')"""
        def decorator(fn: HookFn) -> HookFn:
            self._manual[name] = fn
            return fn
        return decorator

    def register(self, name: str, fn: HookFn):
        """Manual registration."""
        self._manual[name] = fn
        if self._mgr:
            self._mgr.register(name, fn)
    
    def maybe_fire(self, name: str, emu: Any, emit_fn: Optional[Callable] = None) -> bool:
        """Initialize HookManager on first fire and dispatch."""
        if self._mgr is None:
            self._mgr = HookManager(emu)
            # Merge global hooks and manual overrides
            for k, v in self._manual.items():
                self._mgr.register(k, v)
        
        # Ensure emulator is updated if it changed (though usually constant)
        self._mgr.emu = emu
        return self._mgr.maybe_fire(name, emit_fn)

def build_default_registry() -> HookRegistry:
    """Returns a new HookRegistry instance."""
    return HookRegistry()
