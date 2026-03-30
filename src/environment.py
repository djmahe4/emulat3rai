"""
Environment realism module for emulat3rai.

Populates the emulated address space with Windows-like structures
(PEB, TEB, fake FS/GS segments, heap header, etc.) whose complexity
scales with the configured *realism_level*.
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
# Constants
# ---------------------------------------------------------------------------
FAKE_PEB_BASE  = 0x7FFE_0000
FAKE_TEB_BASE  = 0x7FFF_0000
FAKE_HEAP_BASE = 0x0020_0000
FAKE_IMAGE_BASE = 0x0040_0000

PEB_SIZE = 0x500
TEB_SIZE = 0x400

class EnvironmentManager:
    """
    Orchestrates the emulation environment's realism and stealth.
    """
    def __init__(self, emu: Any, cfg: EmulatorConfig):
        self.emu = emu
        self.cfg = cfg
        self._arch = emu.getArchName()  # 'amd64' or 'i386'
        self.stack_base = None
        self.heap_base  = FAKE_HEAP_BASE
        self.peb_base   = FAKE_PEB_BASE
        self.teb_base   = FAKE_TEB_BASE

    def setup(self) -> None:
        """
        Main entry point to configure the environment based on realism_level.
        """
        logger.info("Setting up environment (Realism: %d)", self.cfg.realism_level)
        
        # 1. Reset and fill stack
        self._setup_stack()

        # 2. Level-specific population
        if self.cfg.realism_level >= REALISM_MODERATE:
            self._setup_peb_teb()
        
        if self.cfg.realism_level >= REALISM_HIGH:
            self._setup_heap()
            self._setup_segments_high()

        # 3. Apply general optimizations/emulation options
        self._apply_emu_opts()

        # 4. Stealth: Clean up internal traces
        self.sanitise_guest_env()

    def _setup_stack(self) -> None:
        """TEars down default stack and rebuilds with entropy if needed."""
        # Remove existing [stack]
        memory_snap = self.emu.getMemorySnap()
        for i in range(len(memory_snap) - 1, -1, -1):
            _, _, info, _ = memory_snap[i]
            if info[3] == STACK_MEM_NAME:
                del memory_snap[i]
                self.emu.setMemorySnap(memory_snap)
        self.emu.initStackMemory(stacksize=self.cfg.stack_size)
        self.stack_base = self.emu.stack_map_base
        
        # Fill
        if self.cfg.realism_level >= REALISM_MODERATE:
            fill = self.cfg.make_entropy_bytes(self.cfg.stack_size)
        else:
            fill = b"\x00" * self.cfg.stack_size
        
        self.emu.writeMemory(self.emu.stack_map_base, fill)
        
        # Set initial SP (centred)
        new_sp = self.emu.getStackCounter() - (self.cfg.stack_size // 4)
        self.emu.setStackCounter(new_sp)

    def _setup_peb_teb(self) -> None:
        """Creates PEB/TEB structures and links them."""
        stack_top   = self.emu.stack_map_base + self.cfg.stack_size
        stack_limit = self.emu.stack_map_base

        peb_data = self._build_peb()
        teb_data = self._build_teb(stack_top, stack_limit, FAKE_PEB_BASE, FAKE_TEB_BASE)

        self._add_map(FAKE_PEB_BASE, PEB_SIZE + 0x100, "PEB", peb_data)
        self._add_map(FAKE_TEB_BASE, TEB_SIZE, "TEB", teb_data)

        # Set segment base (FS/GS)
        self._set_teb_segment(FAKE_TEB_BASE)

    def _build_peb(self) -> bytes:
        buf = bytearray(PEB_SIZE)
        # BeingDebugged = 0
        buf[0x02] = 0x00
        
        is_64 = (self._arch == 'amd64')
        if is_64:
            struct.pack_into("<Q", buf, 0x10, FAKE_IMAGE_BASE) # ImageBase
            struct.pack_into("<I", buf, 0x68, 0x00)            # NtGlobalFlag
            struct.pack_into("<I", buf, 0x118, 10)            # Major
        else:
            struct.pack_into("<I", buf, 0x08, FAKE_IMAGE_BASE) # ImageBase
            struct.pack_into("<I", buf, 0x68, 0x00)            # NtGlobalFlag
        
        return bytes(buf)

    def _build_teb(self, stack_top: int, stack_limit: int, 
                   peb_va: int, teb_va: int) -> bytes:
        buf = bytearray(TEB_SIZE)
        is_64 = (self._arch == 'amd64')
        
        if is_64:
            struct.pack_into("<Q", buf, 0x00, 0xFFFFFFFFFFFFFFFF) # ExceptionList
            struct.pack_into("<Q", buf, 0x08, stack_top)          # StackBase
            struct.pack_into("<Q", buf, 0x10, stack_limit)         # StackLimit
            struct.pack_into("<Q", buf, 0x30, teb_va)              # Self
            struct.pack_into("<Q", buf, 0x60, peb_va)              # PEB
        else:
            struct.pack_into("<I", buf, 0x00, 0xFFFFFFFF)        # ExceptionList
            struct.pack_into("<I", buf, 0x04, stack_top)         # StackBase
            struct.pack_into("<I", buf, 0x08, stack_limit)        # StackLimit
            struct.pack_into("<I", buf, 0x18, teb_va)             # Self
            struct.pack_into("<I", buf, 0x30, peb_va)             # PEB

        return bytes(buf)

    def _set_teb_segment(self, teb_va: int) -> None:
        """Sets the appropriate segment (FS for x86, GS for x64)."""
        regname = "gs" if self._arch == "amd64" else "fs"
        try:
            self.emu.setRegisterByName(regname, teb_va)
        except: pass
        
        # MSR fallback for x64
        if self._arch == "amd64":
            try: self.emu.setMsr(0xC0000101, teb_va)
            except: pass

    def _setup_heap(self) -> None:
        heap_size = MEGABYTE
        data = self.cfg.make_entropy_bytes(0x100) + b"\x00" * (heap_size - 0x100)
        self._add_map(FAKE_HEAP_BASE, heap_size, "heap", data)

    def _setup_segments_high(self) -> None:
        """Placeholder for advanced segment descriptor setup."""
        pass

    def _apply_emu_opts(self) -> None:
        if self.cfg.repmax > 0:
            self.emu.setEmuOpt("i386:repmax", self.cfg.repmax)

    def sanitise_guest_env(self) -> None:
        """
        Scans guest memory for any strings starting with EMULAT3RAI_
        and nulls them out to prevent detection.
        """
        pattern = b"EMULAT3RAI_"
        for va, size, perm, name in self.emu.getMemoryMaps():
            if perm & 2: # Writable
                try:
                    data = self.emu.readMemory(va, size)
                    idx = 0
                    while True:
                        idx = data.find(pattern, idx)
                        if idx == -1: break
                        # Found a trace! Null it out until next null or non-printable
                        for i in range(idx, size):
                            if data[i] == 0: break
                            self.emu.writeMemory(va + i, b"\x00")
                        idx += len(pattern)
                except: continue

    def _add_map(self, base: int, size: int, name: str, 
                 data: Optional[bytes] = None, perms: int = 7) -> None:
        size = (size + 0xFFF) & ~0xFFF
        if data is None:
            data = b"\x00" * size
        elif len(data) < size:
            data = data + b"\x00" * (size - len(data))
        else:
            data = data[:size]
        
        try:
            self.emu.addMemoryMap(base, perms, name, data)
        except Exception as exc:
            logger.debug("addMemoryMap(%s) failed: %s", name, exc)

def setup_environment(emu: Any, cfg: EmulatorConfig) -> None:
    """Legacy entry point for backward compatibility."""
    mgr = EnvironmentManager(emu, cfg)
    mgr.setup()
