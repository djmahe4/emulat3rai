"""
Environment realism module for emulat3rai.

Populates the emulated address space with Windows-like structures
(PEB, TEB, fake FS/GS segments, heap header, etc.) whose complexity
scales with the configured *realism_level*:

  REALISM_MINIMAL  (0) – only the stack + code; nothing extra
  REALISM_MODERATE (1) – PEB/TEB stubs, basic FS base, randomised stack
  REALISM_HIGH     (2) – full PEB/TEB fields, LDR list, entropy bytes
"""
from __future__ import annotations

import struct
import random
import logging
from typing import Any, Optional

from .config import EmulatorConfig, REALISM_MINIMAL, REALISM_MODERATE, REALISM_HIGH
from .consts import MEGABYTE, STACK_MEM_NAME

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Memory layout constants (fake but plausible for 64-bit Windows)
# ---------------------------------------------------------------------------
FAKE_PEB_BASE  = 0x7FFE_0000   # actually SharedUserData, but fine for stubs
FAKE_TEB_BASE  = 0x7FFF_0000
FAKE_HEAP_BASE = 0x0020_0000
FAKE_IMAGE_BASE = 0x0040_0000


def _pack64(val: int) -> bytes:
    return struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF)


def _pack32(val: int) -> bytes:
    return struct.pack("<I", val & 0xFFFFFFFF)


def _pack16(val: int) -> bytes:
    return struct.pack("<H", val & 0xFFFF)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _add_map(emu: Any, base: int, size: int, name: str,
             data: Optional[bytes] = None, perms: int = 7) -> None:
    """Add a memory map, ignoring errors (e.g. already mapped)."""
    size = max(size, 0x1000)
    size = (size + 0xFFF) & ~0xFFF
    if data is None:
        data = b"\x00" * size
    elif len(data) < size:
        data = data + b"\x00" * (size - len(data))
    else:
        data = data[:size]
    try:
        emu.addMemoryMap(base, perms, name, data)
    except Exception as exc:
        logger.debug("addMemoryMap(%s) failed: %s", name, exc)


def _write_mem(emu: Any, va: int, data: bytes) -> None:
    try:
        emu.writeMemory(va, data)
    except Exception as exc:
        logger.debug("writeMemory(0x%x) failed: %s", va, exc)


# ---------------------------------------------------------------------------
# Stack initialisation (replaces make_emulator's inline logic)
# ---------------------------------------------------------------------------

def setup_stack(emu: Any, cfg: EmulatorConfig) -> None:
    """
    Re-initialise the emulator stack according to *cfg*.

    Called by environment.setup() after make_emulator() has already created
    the default stack, so we tear it down first.
    """
    # Remove the default [stack] segment
    memory_snap = emu.getMemorySnap()
    for i in range(len(memory_snap) - 1, -1, -1):
        _, _, info, _ = memory_snap[i]
        if info[3] == STACK_MEM_NAME:
            del memory_snap[i]
            emu.setMemorySnap(memory_snap)
            emu.stack_map_base = None
            break

    emu.initStackMemory(stacksize=cfg.stack_size)

    # Fill stack with data depending on realism level
    if cfg.realism_level >= REALISM_MODERATE:
        fill = cfg.make_entropy_bytes(cfg.stack_size)
    else:
        fill = b"\x00" * cfg.stack_size

    emu.writeMemory(emu.stack_map_base, fill)

    # Centre RSP in the stack
    emu.setStackCounter(emu.getStackCounter() - (cfg.stack_size // 4))


# ---------------------------------------------------------------------------
# PEB stub (64-bit)
# ---------------------------------------------------------------------------
# Offsets used by shellcode / malware for anti-analysis checks:
#   +0x00  Reserved (InheritedAddressSpace, etc.)
#   +0x02  BeingDebugged (BYTE) → 0
#   +0x10  ImageBaseAddress
#   +0x18  Ldr (pointer to PEB_LDR_DATA)
#   +0x60  NtGlobalFlag → 0 (debugger sets 0x70)

PEB_SIZE = 0x500

def _build_peb(cfg: EmulatorConfig) -> bytes:
    buf = bytearray(PEB_SIZE)
    # BeingDebugged = 0  (offset 0x02)
    buf[0x02] = 0x00
    # ImageBaseAddress (offset 0x10)
    struct.pack_into("<Q", buf, 0x10, FAKE_IMAGE_BASE)
    # Ldr pointer (offset 0x18) – points just after PEB
    ldr_va = FAKE_PEB_BASE + PEB_SIZE
    struct.pack_into("<Q", buf, 0x18, ldr_va)
    # NtGlobalFlag (offset 0x68 in 64-bit PEB) → 0
    struct.pack_into("<I", buf, 0x68, 0x00)
    # OSMajorVersion (0x118) = 10, OSMinorVersion (0x11c) = 0
    struct.pack_into("<I", buf, 0x118, 10)
    struct.pack_into("<I", buf, 0x11c, 0)
    return bytes(buf)


# ---------------------------------------------------------------------------
# TEB stub (64-bit)
# ---------------------------------------------------------------------------
# Key offsets:
#   +0x00  NT_TIB.ExceptionList  → 0xFFFFFFFFFFFFFFFF (end-of-chain)
#   +0x08  NT_TIB.StackBase      → top of stack
#   +0x10  NT_TIB.StackLimit     → bottom of stack
#   +0x30  Self (pointer to TEB itself)
#   +0x60  PEB pointer

TEB_SIZE = 0x400

def _build_teb(stack_base: int, stack_limit: int,
               peb_va: int, teb_va: int) -> bytes:
    buf = bytearray(TEB_SIZE)
    # ExceptionList = end-of-chain sentinel
    struct.pack_into("<Q", buf, 0x00, 0xFFFFFFFFFFFFFFFF)
    # StackBase (grows downwards on x64 Windows, so "base" is the high address)
    struct.pack_into("<Q", buf, 0x08, stack_base)
    # StackLimit
    struct.pack_into("<Q", buf, 0x10, stack_limit)
    # Self pointer
    struct.pack_into("<Q", buf, 0x30, teb_va)
    # PEB pointer
    struct.pack_into("<Q", buf, 0x60, peb_va)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def setup_environment(emu: Any, cfg: EmulatorConfig) -> None:
    """
    Apply environment realism to *emu* according to *cfg.realism_level*.

    This is called once after make_emulator() has created the emulator object
    but before stepping begins.
    """
    if cfg.realism_level == REALISM_MINIMAL:
        # Only re-do the stack (same as original emulator.py, but uses cfg)
        setup_stack(emu, cfg)
        _apply_repmax(emu, cfg)
        return

    # --- REALISM_MODERATE / HIGH ---
    setup_stack(emu, cfg)
    _apply_repmax(emu, cfg)
    _setup_peb_teb(emu, cfg)

    if cfg.realism_level >= REALISM_HIGH:
        _setup_heap(emu, cfg)
        _setup_gs(emu)


def _apply_repmax(emu: Any, cfg: EmulatorConfig) -> None:
    if cfg.repmax > 0:
        emu.setEmuOpt("i386:repmax", cfg.repmax)


def _setup_peb_teb(emu: Any, cfg: EmulatorConfig) -> None:
    # Stack limits for TEB
    stack_base  = emu.stack_map_base + cfg.stack_size   # high address
    stack_limit = emu.stack_map_base                    # low address

    peb_data = _build_peb(cfg)
    teb_data = _build_teb(stack_base, stack_limit, FAKE_PEB_BASE, FAKE_TEB_BASE)

    _add_map(emu, FAKE_PEB_BASE, PEB_SIZE + 0x100, "PEB", peb_data)
    _add_map(emu, FAKE_TEB_BASE, TEB_SIZE,          "TEB", teb_data)

    # Point GS:[0x30] at the TEB (Windows 64-bit TEB self pointer via GS)
    _set_gs_base(emu, FAKE_TEB_BASE)


def _set_gs_base(emu: Any, teb_va: int) -> None:
    """Set GS base to point at the TEB."""
    try:
        # envi exposes segment bases via setRegisterByName on some builds
        emu.setRegisterByName("gs", teb_va)
    except Exception:
        pass
    try:
        # MSR 0xC0000101 = GS_BASE; not universally exposed but try anyway
        emu.setMsr(0xC0000101, teb_va)
    except Exception:
        pass


def _setup_gs(emu: Any) -> None:
    """For REALISM_HIGH: map a GS-accessible page at FAKE_TEB_BASE."""
    # Already done via _set_gs_base in _setup_peb_teb; nothing extra needed.
    pass


def _setup_heap(emu: Any, cfg: EmulatorConfig) -> None:
    """Map a fake heap region for REALISM_HIGH."""
    heap_size = MEGABYTE  # 1 MB fake heap
    if cfg.realism_level >= REALISM_HIGH:
        heap_data = cfg.make_entropy_bytes(0x40) + b"\x00" * (heap_size - 0x40)
    else:
        heap_data = b"\x00" * heap_size
    _add_map(emu, FAKE_HEAP_BASE, heap_size, "heap", heap_data)
