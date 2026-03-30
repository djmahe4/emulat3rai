import os
import vivisect
import viv_utils
from rich import print as rprint
from typing import Optional

from .misc import *
from .emulator import *
from .config import EmulatorConfig
from .analyzer import resolve_function_name, list_functions, print_static_disasm


def load_shellcode_bytes(path: str, is_hex: bool) -> bytes:
    """Read shellcode from a file. Supports raw binary or hex-encoded."""
    with open(path, "rb") as f:
        raw = f.read()
    if is_hex:
        text = raw.decode("ascii", errors="ignore")
        text = text.replace("\\x", "").replace(" ", "").replace("\n", "").replace("\r", "")
        return bytes.fromhex(text)
    return raw

def get_arch(vw) -> str:
    return vw.getMeta("Architecture")

def emulate_pe(pe_path: str, function_va: Optional[int] = None, max_instructions: int = 200,
               follow_calls: bool = False, follow_va: Optional[int] = None,
               stack_context: int = 4, cfg: Optional[EmulatorConfig] = None):
    """Load a PE and step through a function."""
    suppress_viv_logging()
    rprint(f"[[cyan]*[/cyan]] Loading [green]{os.path.basename(pe_path)}[/green] into vivisect workspace")
    vw = viv_utils.getWorkspace(pe_path)
    rprint(f"[[magenta]*[/magenta]] Architecture: {get_arch(vw)}")

    if function_va is None:
        function_va = vw.getEntryPoints()[0]
        rprint(f"[[red]*[/red]] No function VA given, using entry point: [green]0x{function_va:x}[/green]")
    else:
        rprint(f"[[red]*[/red]] Target function: [blue]0x{function_va:x}[blue]")

    try:
        fname = resolve_function_name(vw, function_va) or "(unnamed)"
        rprint(f"[[yellow]*[/yellow]] Function name: {fname}")
    except Exception:
        rprint(f"[[yellow]*[/yellow]] Address [yellow]0x{function_va:x}[/yellow] is not a function entry (mid-function start)")

    print_static_disasm(vw, function_va)

    rprint(f"[[green]*[/green]] Creating emulator, stepping up to {max_instructions} instructions...")
    if follow_va is not None:
        rprint(f"[[cyan]*[/cyan]] Following calls to 0x{follow_va:x}")
    elif follow_calls:
        rprint(f"[[cyan]*[/cyan]] Following calls into subroutines")

    if cfg is None:
        cfg = EmulatorConfig(
            max_instructions=max_instructions,
            follow_calls=follow_calls,
            follow_va=follow_va,
            stack_context=stack_context,
        )

    emu = make_emulator(vw, cfg)
    wlog_baseline = len(emu.getPathProp("writelog"))
    steps = step_emulator(emu, function_va, max_instructions, stop_on_ret=True,
                          follow_calls=follow_calls or (follow_va is not None),
                          follow_va=follow_va, vw=vw, stack_context=stack_context,
                          cfg=cfg)

    if cfg.json_output:
        from .session import emu_state_to_json
        rprint("\n[JSON output]")
        rprint(emu_state_to_json(emu, function_va, steps, cfg,
                                 baseline_wlog_len=wlog_baseline))