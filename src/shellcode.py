import viv_utils
from rich import print as rprint

from .consts import *
from .misc import *
from .emulator import *
from .config import EmulatorConfig
from .analyzer import hexdump

def emulate_shellcode(
    sc_bytes: bytes,
    cfg: Optional[EmulatorConfig] = None,
    **kwargs,
):
    """
    Load raw x64 shellcode into a vivisect workspace and step through it.

    This uses the same approach as FLOSS for shellcode analysis
    (see floss/main.py which calls viv_utils.getShellcodeWorkspace).
    """
    if cfg is None:
        cfg = EmulatorConfig(
            max_instructions=kwargs.get("max_instructions", MAX_INST_SIZE),
            stack_context=kwargs.get("stack_context", STACK_CTX),
            sc_base=kwargs.get("base", DEFAULT_SC_BASE),
            sc_entry_offset=kwargs.get("entry_offset", 0),
            stop_on_ret=False,
        )

    base = cfg.sc_base
    entry_offset = cfg.sc_entry_offset
    max_instructions = cfg.max_instructions
    sc_size = len(sc_bytes)

    inst_num = 0 
    suppress_viv_logging()

    entry_point = base + entry_offset

    rprint(f"\n[[yellow]*[/yellow]] Shellcode Size:     {sc_size} bytes")
    rprint(f"[[yellow]*[/yellow]] Base address:       0x{base:x}")
    rprint(f"[[yellow]*[/yellow]] Entry point:        0x{entry_point:x}")

    # hex dump of the shellcode
    if sc_size <= 256:
        rprint(f"\n[[magenta]*[/magenta]] Shellcode hex dump:")
        rprint(hexdump(sc_bytes, base))
    else:
        rprint(f"\n[[magenta]*[/magenta]] Shellcode hex dump (first 256 bytes of {sc_size}):")
        rprint(hexdump(sc_bytes[:256], base))
    rprint()

    # load into vivisect as x64 shellcode
    rprint(f"[[green]*[/green]] Loading shellcode into vivisect workspace...")
    vw = viv_utils.getShellcodeWorkspace(sc_bytes, "amd64", base=base, entry_point=entry_offset)

    # static disassembly from entry point
    rprint(f"[[blue]*[/blue]] Static disassembly from entry point:\n")
    va = entry_point
    for _ in range(max_instructions):
        if va >= base + sc_size:
            break
        try:
            op = vw.parseOpcode(va)
            rprint(f"  0x{va:016x}:  {op}")
            va += len(op)
            inst_num += 1
        except Exception:
            rprint(f"  0x{va:016x}:  <invalid>")
            break
    rprint()

    rprint(f"[*] total number of instructions: {inst_num}")
    rprint(f"[[magenta]*[/magenta]] Creating emulator, stepping up to {max_instructions} instructions...")

    emu = make_emulator(vw, cfg)
    wlog_baseline = len(emu.getPathProp("writelog"))

    # for shellcode, don't stop on ret by default (shellcode may use ret as a trick)
    steps = step_emulator(
        emu,
        entry_point,
        max_instructions=cfg.max_instructions,
        stop_on_ret=False,
        vw=vw,
        stack_context=cfg.stack_context,
        cfg=cfg,
    )

    if cfg.json_output:
        from .session import emu_state_to_json
        rprint("\n[JSON output]")
        rprint(emu_state_to_json(emu, entry_point, steps, cfg,
                                 baseline_wlog_len=wlog_baseline))

