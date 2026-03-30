"""
Helper analysis tools for emulat3rai.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Function name resolution
# ---------------------------------------------------------------------------

def resolve_function_name(vw: Any, fva: int) -> Optional[str]:
    """Resolve function name using multiple vivisect methods."""
    import viv_utils

    name = vw.getName(fva)
    if name and not name.startswith("sub_"):
        suffix = f"_{fva:x}"
        if name.endswith(suffix):
            name = name[: -len(suffix)]
        return name

    api_name = viv_utils.get_function_name(vw, fva)
    if api_name:
        return api_name

    return None


# ---------------------------------------------------------------------------
# Function listing
# ---------------------------------------------------------------------------

def list_functions(pe_path: str) -> None:
    """Print all functions in the workspace."""
    import viv_utils
    from rich import print as rprint

    vw = viv_utils.getWorkspace(pe_path)
    functions = sorted(vw.getFunctions())
    rprint(f"[[yellow]*[/yellow]] [green]{len(functions)}[/green] functions found:\n")
    rprint(f"  {'VA':<20s}  {'Size':>5s}  Name")
    rprint(f"  {'-' * 18}  {'-' * 5}  {'-' * 40}")
    for fva in functions:
        name = resolve_function_name(vw, fva) or "(unnamed)"
        try:
            size = vw.getFunctionMetaDict(fva).get("Size", 0)
        except Exception:
            size = 0
        rprint(f"  0x{fva:016x}  {size:>5d}  {name}")


# ---------------------------------------------------------------------------
# Static disassembly helpers
# ---------------------------------------------------------------------------

def static_disasm(vw: Any, fva: int, max_insn: int = 500) -> List[Tuple[int, str]]:
    """
    Return a list of (va, insn_str) tuples for the function starting at *fva*.
    Falls back to a linear scan if viv_utils.Function fails.
    """
    import viv_utils

    results: List[Tuple[int, str]] = []
    try:
        f = viv_utils.Function(vw, fva)
        for bb in f.basic_blocks:
            for insn in bb.instructions:
                results.append((insn.va, str(insn)))
    except Exception:
        va = fva
        for _ in range(max_insn):
            try:
                op = vw.parseOpcode(va)
                results.append((va, str(op)))
                va += len(op)
            except Exception:
                break
    return results


def print_static_disasm(vw: Any, fva: int) -> int:
    """Pretty-print static disassembly of the function at *fva*.  Returns insn count."""
    from rich import print as rprint

    insns = static_disasm(vw, fva)
    if not insns:
        rprint("[[red]*[/red]] Could not statically disassemble function\n")
        return 0
    rprint(f"[[blue]*[/blue]] Static disassembly ({len(insns)} instructions):\n")
    for va, insn in insns:
        rprint(f"  0x{va:016x}:  {insn}")
    rprint()
    return len(insns)


# ---------------------------------------------------------------------------
# Hex dump
# ---------------------------------------------------------------------------

def hexdump(data: bytes, base_addr: int = 0, width: int = 16) -> str:
    """Return a classic hex dump string."""
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        lines.append(f"  0x{base_addr + offset:08x}: {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Import table extraction
# ---------------------------------------------------------------------------

def get_imports(vw: Any) -> Dict[str, int]:
    """Return {symbol_name: va} for all imports in *vw*."""
    imports: Dict[str, int] = {}
    try:
        for va, size, ltype, linfo in vw.getLocations():
            if ltype == vw.LOC_IMPORT:
                name = vw.getName(va) or ""
                imports[name] = va
    except Exception:
        pass
    # Alternative: iterate file metadata
    try:
        for lib, func, va in vw.getImports():
            key = f"{lib}.{func}" if lib else func
            imports[key] = va
    except Exception:
        pass
    return imports


# ---------------------------------------------------------------------------
# is_safe_to_follow (kept here so emulator.py can import it)
# ---------------------------------------------------------------------------

def is_safe_to_follow(vw: Any, emu: Any, op: Any) -> bool:
    """
    Decide whether a call should be followed.
    Returns True only for non-library functions defined in the workspace.
    """
    try:
        target = op.getOperValue(0, emu)
    except Exception:
        return False

    if target is None or target == 0:
        return False

    if target not in vw.getFunctions():
        # Try to create it – some functions are not yet analysed
        try:
            vw.makeFunction(target)
        except Exception:
            return False
        if target not in vw.getFunctions():
            return False

    try:
        import viv_utils.flirt
        if viv_utils.flirt.is_library_function(vw, target):
            return False
    except Exception:
        pass

    return True
