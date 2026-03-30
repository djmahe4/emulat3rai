"""
Runtime configuration for emulat3rai.

Centralises every tunable knob so callers can pass a single Config object
instead of a growing list of keyword arguments.
"""
from __future__ import annotations

import os
import random
from dataclasses import dataclass
from typing import Optional

from .consts import MAX_INST_SIZE, STACK_CTX, MEGABYTE


# ---------------------------------------------------------------------------
# Realism level constants
# ---------------------------------------------------------------------------
REALISM_MINIMAL  = 0   # bare-bones vivisect defaults
REALISM_MODERATE = 1   # randomised stack, basic PEB/TEB stubs, realistic rep limit
REALISM_HIGH     = 2   # full PEB/TEB, FS/GS populated, entropy bytes in stack


# ---------------------------------------------------------------------------
# Crash-mode constants
# ---------------------------------------------------------------------------
CRASH_ROLLBACK = "rollback"   # restore full pre-crash snapshot (original behaviour)
CRASH_PARTIAL  = "partial"    # keep memory writes, reset registers only
CRASH_CONTINUE = "continue"   # log crash and keep going


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------
@dataclass
class EmulatorConfig:
    """All runtime knobs for emulat3rai."""

    # --- execution limits ---
    max_instructions: int = MAX_INST_SIZE
    repmax: int = 256           # max REP-prefix iterations per step; 0 = unlimited
    follow_calls: bool = False
    follow_va: Optional[int] = None
    follow_depth: int = 5       # max call-follow depth (0 = unlimited)

    # --- stack ---
    stack_size: int = 524288    # 512 KB default (0.5 * MEGABYTE)
    stack_context: int = STACK_CTX

    # --- realism ---
    realism_level: int = REALISM_MINIMAL
    # seed for deterministic "random" stack garbage; None = truly random each run
    entropy_seed: Optional[int] = None

    # --- crash handling ---
    crash_mode: str = CRASH_ROLLBACK

    # --- output ---
    json_output: bool = False
    interactive: bool = False

    # --- shellcode-specific ---
    sc_base: int = 0x690000
    sc_entry_offset: int = 0
    sc_hex_file: bool = False     # file contains hex text, not raw bytes

    # --- stop-on-ret ---
    stop_on_ret: bool = True

    def __post_init__(self) -> None:
        if self.crash_mode not in (CRASH_ROLLBACK, CRASH_PARTIAL, CRASH_CONTINUE):
            raise ValueError(f"Unknown crash_mode: {self.crash_mode!r}")
        if self.realism_level not in (REALISM_MINIMAL, REALISM_MODERATE, REALISM_HIGH):
            raise ValueError(f"Unknown realism_level: {self.realism_level}")
        # Ensure stack is at least 128 KB
        if self.stack_size < 128 * 1024:
            self.stack_size = 128 * 1024

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def make_entropy_bytes(self, size: int) -> bytes:
        """Return *size* pseudo-random bytes (respects entropy_seed)."""
        rng = random.Random(self.entropy_seed)
        return bytes(rng.randint(0, 255) for _ in range(size))

    @classmethod
    def from_args(cls, args) -> "EmulatorConfig":
        """Build a config from argparse Namespace produced by cliargs.build_parser()."""
        return cls(
            max_instructions=args.max,
            follow_calls=args.follow_calls,
            follow_va=args.follow_va,
            follow_depth=args.follow_depth,
            stack_size=args.stack_size,
            stack_context=args.stack_context,
            realism_level=args.realism_level,
            crash_mode=args.crash_mode,
            json_output=args.json_output,
            interactive=args.interactive,
            repmax=args.repmax,
            stop_on_ret=True,
        )
