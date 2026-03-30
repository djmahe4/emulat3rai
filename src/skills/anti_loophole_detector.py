"""
Skill: Anti-Loophole Detector

Monitors REP-prefixed instructions and backward jumps that could cause
runaway emulation (large loop counts, infinite loops, etc.).

Usage::

    from src.skills import AntiLoopholeDetector

    detector = AntiLoopholeDetector(warn_threshold=100, abort_threshold=10000)
    session.set_observer(detector)
    session.run()

    if detector.loopholes:
        for item in detector.loopholes:
            print(item)
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..observers import BaseObserver, EVT_INSTRUCTION


class AntiLoopholeDetector(BaseObserver):
    """
    Observer that detects potential loophole instructions during emulation.

    Tracks:
    - REP-prefixed instructions (rep movsb, rep stosb, etc.)
    - Backward branches that may form infinite loops
    - Consecutive visits to the same address (loop counter)
    """

    def __init__(self, warn_threshold: int = 50,
                 abort_threshold: int = 5000) -> None:
        """
        Args:
            warn_threshold:  log a warning after this many visits to one VA
            abort_threshold: after this many visits, flag as a hard loophole
        """
        self.warn_threshold  = warn_threshold
        self.abort_threshold = abort_threshold

        self._visit_counts: Dict[int, int] = {}
        self.loopholes: List[Dict] = []
        self.warnings:  List[Dict] = []

    # ------------------------------------------------------------------
    def on_instruction(self, *, event: str, step: int, va: int,
                       insn: str, emu: Any, **kwargs: Any) -> None:
        count = self._visit_counts.get(va, 0) + 1
        self._visit_counts[va] = count

        insn_lower = insn.lower().strip()

        # --- REP-prefix detection ---
        if insn_lower.startswith("rep"):
            entry = {
                "kind":  "rep_instruction",
                "step":  step,
                "va":    f"0x{va:x}",
                "insn":  insn,
                "visits": count,
            }
            self.warnings.append(entry)

        # --- high-visit-count detection ---
        if count == self.warn_threshold:
            self.warnings.append({
                "kind":  "hot_address_warning",
                "step":  step,
                "va":    f"0x{va:x}",
                "insn":  insn,
                "visits": count,
            })

        if count >= self.abort_threshold:
            entry = {
                "kind":  "infinite_loop_detected",
                "step":  step,
                "va":    f"0x{va:x}",
                "insn":  insn,
                "visits": count,
            }
            if entry not in self.loopholes:
                self.loopholes.append(entry)

    # ------------------------------------------------------------------
    def report(self) -> str:
        lines = [f"AntiLoopholeDetector report"]
        lines.append(f"  Unique addresses visited: {len(self._visit_counts)}")
        lines.append(f"  Warnings:  {len(self.warnings)}")
        lines.append(f"  Loopholes: {len(self.loopholes)}")
        if self.loopholes:
            lines.append("  Detected loopholes:")
            for item in self.loopholes:
                lines.append(f"    [{item['kind']}] step={item['step']} "
                              f"va={item['va']} insn={item['insn']!r} "
                              f"visits={item['visits']}")
        return "\n".join(lines)
