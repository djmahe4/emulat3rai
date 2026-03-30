"""
Runtime configuration for emulat3rai.

Centralises every tunable knob so callers can pass a single Config object
instead of a growing list of keyword arguments.
"""
from __future__ import annotations
import os
import random
import json
from dataclasses import dataclass, asdict
from typing import Optional, Any

from .consts import MAX_INST_SIZE, STACK_CTX

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
# Size constants
# ---------------------------------------------------------------------------
MEGABYTE = 1024 * 1024        # 1 MiB — used for stack/heap size calculations

# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------
@dataclass
class EmulatorConfig:
    """
    Centralised runtime configuration for emulat3rai.
    Supports serialization and environment-based overrides for stealth/internal flags.
    """

    # --- execution limits ---
    max_instructions: int = MAX_INST_SIZE
    repmax: int = 256           # max REP-prefix iterations per step; 0 = unlimited
    follow_calls: bool = False
    follow_va: Optional[int] = None
    follow_depth: int = 5       # max call-follow depth (0 = unlimited)

    # --- stack ---
    stack_size: int = 524288    # 512 KB default
    stack_context: int = STACK_CTX

    # --- realism ---
    realism_level: int = REALISM_MINIMAL
    entropy_seed: Optional[int] = None

    # --- crash handling ---
    crash_mode: str = CRASH_ROLLBACK

    # --- environment/stealth (hidden flags) ---
    internal_mode: bool = False # can be set via EMULAT3RAI_INTERNAL env var

    # --- output ---
    json_output: bool = False
    interactive: bool = False

    # --- shellcode-specific ---
    sc_base: int = 0x690000
    sc_entry_offset: int = 0
    sc_hex_file: bool = False

    # --- stop-on-ret ---
    stop_on_ret: bool = True

    def __post_init__(self) -> None:
        """Apply validations and environment overrides."""
        # --- Environment Overrides (Dev/Stealth) ---
        if os.getenv("EMULAT3RAI_INTERNAL") == "true":
            self.internal_mode = True

        # --- Validations ---
        if self.crash_mode not in (CRASH_ROLLBACK, CRASH_PARTIAL, CRASH_CONTINUE):
            raise ValueError(f"Unknown crash_mode: {self.crash_mode!r}")
        if self.realism_level not in (REALISM_MINIMAL, REALISM_MODERATE, REALISM_HIGH):
            raise ValueError(f"Unknown realism_level: {self.realism_level}")
        
        # Guard rails for stack and limits
        if self.stack_size < 4096:
            self.stack_size = 4096
        if self.repmax < 0:
            self.repmax = 0

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary for JSON export."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EmulatorConfig:
        """Create config from dictionary."""
        return cls(**data)

    def to_json(self, indent: int = 4) -> str:
        """Export config as JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def make_entropy_bytes(self, size: int) -> bytes:
        """Return pseudo-random bytes (respects entropy_seed)."""
        rng = random.Random(self.entropy_seed)
        return bytes(rng.randint(0, 255) for _ in range(size))

    @classmethod
    def from_args(cls, args) -> EmulatorConfig:
        """Build config from argparse Namespace (deprecated, prefer from_dict)."""
        return cls(
            max_instructions=getattr(args, 'max', MAX_INST_SIZE),
            follow_calls=getattr(args, 'follow_calls', False),
            follow_va=getattr(args, 'follow_va', None),
            follow_depth=getattr(args, 'follow_depth', 5),
            stack_size=getattr(args, 'stack_size', 524288),
            stack_context=getattr(args, 'stack_context', STACK_CTX),
            realism_level=getattr(args, 'realism_level', REALISM_MINIMAL),
            crash_mode=getattr(args, 'crash_mode', CRASH_ROLLBACK),
            json_output=getattr(args, 'json_output', False),
            interactive=getattr(args, 'interactive', False),
            repmax=getattr(args, 'repmax', 256),
            stop_on_ret=True,
        )
