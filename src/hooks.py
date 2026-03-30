"""
API hooks registry for emulat3rai.

Hooks intercept calls to well-known Windows API functions that vivisect
would otherwise treat as opaque no-ops.  Each hook:
  1. Reads its arguments from the emulator registers / stack.
  2. Performs a simulated action (e.g. allocate memory, return a fake handle).
  3. Returns a sensible value in RAX.
  4. Emits an EVT_HOOK_FIRED event so observers can log it.

Usage (from EmulatorSession)::

    registry = HookRegistry()
    registry.register("VirtualAlloc", virtual_alloc_hook)
    ...
    if registry.maybe_fire(name, emu, emit_fn):
        continue  # hook handled the call
"""
from __future__ import annotations

import struct
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Hook function signature: hook(emu, args: tuple) -> int (return value for RAX)
HookFn = Callable[[Any, tuple], int]


# ---------------------------------------------------------------------------
# HookRegistry
# ---------------------------------------------------------------------------
class HookRegistry:
    """Central registry mapping API names → hook callables."""

    def __init__(self) -> None:
        self._hooks: Dict[str, HookFn] = {}

    def register(self, name: str, fn: HookFn) -> None:
        self._hooks[name] = fn

    def hook(self, name: str) -> Callable[[HookFn], HookFn]:
        """Decorator: @registry.hook('AllocateMemory')"""
        def decorator(fn: HookFn) -> HookFn:
            self.register(name, fn)
            return fn
        return decorator

    def maybe_fire(self, name: str, emu: Any,
                   emit_fn: Optional[Callable] = None) -> bool:
        """
        If *name* is registered, call the hook and set RAX to its return
        value.  Returns True if the hook fired.
        """
        fn = self._hooks.get(name)
        if fn is None:
            return False

        # read first 4 args from Win64 calling convention (rcx, rdx, r8, r9)
        try:
            args = (
                emu.getRegisterByName("rcx"),
                emu.getRegisterByName("rdx"),
                emu.getRegisterByName("r8"),
                emu.getRegisterByName("r9"),
            )
        except Exception:
            args = (0, 0, 0, 0)

        try:
            ret_val = fn(emu, args)
        except Exception as exc:
            logger.debug("Hook %s raised: %s", name, exc)
            ret_val = 0

        try:
            emu.setRegisterByName("rax", ret_val & 0xFFFFFFFFFFFFFFFF)
        except Exception:
            pass

        if emit_fn is not None:
            emit_fn(hook_name=name, args=args, ret_val=ret_val, emu=emu)

        return True

    def registered_names(self) -> List[str]:
        return list(self._hooks.keys())


# ---------------------------------------------------------------------------
# Default hook implementations
# ---------------------------------------------------------------------------

# Fake handle base – increment for each fake object handed out
_FAKE_HANDLE_BASE = 0x4000
_fake_handle_counter = _FAKE_HANDLE_BASE


def _next_handle() -> int:
    global _fake_handle_counter
    _fake_handle_counter += 4
    return _fake_handle_counter


def _emu_alloc(emu: Any, size: int, perms: int = 7) -> int:
    """Allocate *size* bytes in the emulator's address space."""
    import envi.memory as em
    size = max(size, 0x1000)
    size = (size + 0xFFF) & ~0xFFF      # page-align
    # pick an unused base address
    base = 0x10000000
    try:
        maps = [m[0] for m in emu.getMemoryMaps()]
        if maps:
            base = max(maps) + 0x10000
            base = (base + 0xFFFF) & ~0xFFFF
    except Exception:
        pass
    try:
        emu.addMemoryMap(base, perms, "heap_alloc", b"\x00" * size)
    except Exception:
        pass
    return base


# ------ individual hooks -------

def hook_virtual_alloc(emu: Any, args: tuple) -> int:
    """VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect) → ptr"""
    _lp_address, dw_size, _alloc_type, _protect = args
    size = dw_size if dw_size > 0 else 0x1000
    return _emu_alloc(emu, size)


def hook_virtual_alloc_ex(emu: Any, args: tuple) -> int:
    """VirtualAllocEx(hProcess, lpAddress, dwSize, flType, flProtect) → ptr"""
    # args[0] = hProcess (ignored), args[1] = lpAddress, args[2] = dwSize
    dw_size = args[2] if len(args) > 2 else 0
    size = dw_size if dw_size > 0 else 0x1000
    return _emu_alloc(emu, size)


def hook_heap_alloc(emu: Any, args: tuple) -> int:
    """HeapAlloc(hHeap, dwFlags, dwBytes) → ptr"""
    _h_heap, _flags, dw_bytes = args[:3]
    size = dw_bytes if dw_bytes > 0 else 0x100
    return _emu_alloc(emu, size)


def hook_get_proc_address(emu: Any, args: tuple) -> int:
    """GetProcAddress(hModule, lpProcName) → fake function pointer"""
    # Return a fake non-zero address so callers can store it and call it
    return _next_handle()


def hook_load_library(emu: Any, args: tuple) -> int:
    """LoadLibraryA/W(lpFileName) → fake module handle"""
    return _next_handle()


def hook_get_module_handle(emu: Any, args: tuple) -> int:
    """GetModuleHandleA/W(lpModuleName) → fake handle (or 0 for NULL)"""
    # NULL means "current module" – return something non-zero
    return _next_handle()


def hook_nt_query_system_information(emu: Any, args: tuple) -> int:
    """NtQuerySystemInformation → STATUS_SUCCESS (0)"""
    return 0


def hook_virtual_protect(emu: Any, args: tuple) -> int:
    """VirtualProtect → TRUE (1)"""
    return 1


def hook_create_file(emu: Any, args: tuple) -> int:
    """CreateFileA/W → fake handle"""
    return _next_handle()


def hook_read_file(emu: Any, args: tuple) -> int:
    """ReadFile → TRUE (1)"""
    return 1


def hook_write_file(emu: Any, args: tuple) -> int:
    """WriteFile → TRUE (1)"""
    return 1


def hook_close_handle(emu: Any, args: tuple) -> int:
    """CloseHandle → TRUE (1)"""
    return 1


def hook_is_debugger_present(emu: Any, args: tuple) -> int:
    """IsDebuggerPresent → FALSE (0) (anti-anti-debug)"""
    return 0


def hook_check_remote_debugger(emu: Any, args: tuple) -> int:
    """CheckRemoteDebuggerPresent → sets *pbDebuggerPresent=FALSE, returns TRUE"""
    # args[1] = lpbDebuggerPresent pointer
    try:
        ptr = args[1]
        if ptr:
            emu.writeMemory(ptr, b"\x00\x00\x00\x00")
    except Exception:
        pass
    return 1


def hook_output_debug_string(emu: Any, args: tuple) -> int:
    return 0


def hook_exit_process(emu: Any, args: tuple) -> int:
    """ExitProcess – raise a special exception to stop emulation cleanly."""
    raise _ExitProcessCalled(args[0])


class _ExitProcessCalled(Exception):
    """Raised by hook_exit_process to cleanly terminate emulation."""
    def __init__(self, exit_code: int = 0):
        super().__init__(f"ExitProcess({exit_code})")
        self.exit_code = exit_code


# ---------------------------------------------------------------------------
# Build the default registry
# ---------------------------------------------------------------------------

def build_default_registry() -> HookRegistry:
    """Return a HookRegistry pre-loaded with common Windows API stubs."""
    reg = HookRegistry()

    entries: List[Tuple[str, HookFn]] = [
        # memory allocation
        ("VirtualAlloc",                    hook_virtual_alloc),
        ("VirtualAllocEx",                  hook_virtual_alloc_ex),
        ("HeapAlloc",                       hook_heap_alloc),
        ("RtlAllocateHeap",                 hook_heap_alloc),
        # library / module
        ("GetProcAddress",                  hook_get_proc_address),
        ("LoadLibraryA",                    hook_load_library),
        ("LoadLibraryW",                    hook_load_library),
        ("LoadLibraryExA",                  hook_load_library),
        ("LoadLibraryExW",                  hook_load_library),
        ("GetModuleHandleA",                hook_get_module_handle),
        ("GetModuleHandleW",                hook_get_module_handle),
        # protection / query
        ("VirtualProtect",                  hook_virtual_protect),
        ("VirtualProtectEx",                hook_virtual_protect),
        ("NtQuerySystemInformation",        hook_nt_query_system_information),
        ("ZwQuerySystemInformation",        hook_nt_query_system_information),
        # file I/O
        ("CreateFileA",                     hook_create_file),
        ("CreateFileW",                     hook_create_file),
        ("ReadFile",                        hook_read_file),
        ("WriteFile",                       hook_write_file),
        ("CloseHandle",                     hook_close_handle),
        # anti-debug
        ("IsDebuggerPresent",               hook_is_debugger_present),
        ("CheckRemoteDebuggerPresent",      hook_check_remote_debugger),
        ("OutputDebugStringA",              hook_output_debug_string),
        ("OutputDebugStringW",              hook_output_debug_string),
        # process
        ("ExitProcess",                     hook_exit_process),
    ]

    for name, fn in entries:
        reg.register(name, fn)

    return reg
