import sys
import logging
import argparse

from .consts import *
from .config import (
    REALISM_MINIMAL, REALISM_MODERATE, REALISM_HIGH,
    CRASH_ROLLBACK, CRASH_PARTIAL, CRASH_CONTINUE,
    MEGABYTE,
)

def build_parser():
    parser = argparse.ArgumentParser(
        description="emulat3rai – modular x64 instruction-level emulator (PE & shellcode)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --pe xor.exe                                          # PE entry point
  %(prog)s --pe xor.exe --va 0x140001010 --max 100               # specific function
  %(prog)s --pe xor.exe --list                                   # list functions
  %(prog)s --pe xor.exe --va 0x1400014c1 --follow-va 0x140001450 # follow one call
  %(prog)s --pe xor.exe --va 0x1400014c1 --follow-calls          # follow all calls
  %(prog)s --shellcode payload.bin                               # x64 raw shellcode
  %(prog)s --shellcode payload.bin --max 500                     # shellcode, 500 steps
  %(prog)s --shellcode encoded.txt --hex                         # hex-encoded file
  %(prog)s --sc-hex "4831c04889c7c3"                             # inline hex shellcode
  %(prog)s --sc-hex "\\x48\\x31\\xc0\\xc3"                           # \\x notation
  %(prog)s --pe xor.exe --realism-level 2 --stack-size 2097152   # high realism
  %(prog)s --pe xor.exe --crash-mode continue --json-output      # JSON output
""",
    )

    # PE mode arguments
    pe_group = parser.add_argument_group("PE mode")
    pe_group.add_argument("--pe", metavar="FILE", help="PE file to analyze")
    pe_group.add_argument("--va", type=lambda x: int(x, 0),
                          help="function VA to emulate (hex, default: entry point)")
    pe_group.add_argument("--list", action="store_true", help="list all functions and exit")

    # shellcode mode arguments
    sc_group = parser.add_argument_group("shellcode mode")
    sc_group.add_argument("--shellcode", "-s", metavar="FILE", help="shellcode file (raw binary)")
    sc_group.add_argument("--sc-hex", metavar="HEX", help="inline hex shellcode string")
    sc_group.add_argument("--hex", action="store_true", help="shellcode file is hex-encoded (not raw)")
    sc_group.add_argument("--base", "-b", type=lambda x: int(x, 0), default=DEFAULT_SC_BASE,
                          help=f"base address (default: 0x{DEFAULT_SC_BASE:x})")
    sc_group.add_argument("--entry", "-e", type=lambda x: int(x, 0), default=0,
                          help="entry point offset from base (default: 0)")

    # common arguments
    parser.add_argument("--max", "-m", type=int, default=MAX_INST_SIZE,
                        help="max instructions (default: 200)")
    parser.add_argument("--follow-calls", "-f", action="store_true",
                        help="step into call instructions instead of skipping them")
    parser.add_argument("--follow-va", type=lambda x: int(x, 0),
                        help="only step into calls to this specific address (hex)")
    parser.add_argument("--follow-depth", type=int, default=5, metavar="N",
                        help="max call-follow depth (default: 5)")
    parser.add_argument("--stack-context", type=int, default=STACK_CTX, metavar="N",
                        help="show N qwords before and after RSP each step (0 to hide, default: 4)")

    # realism / environment
    real_group = parser.add_argument_group("environment realism")
    real_group.add_argument(
        "--realism-level", type=int, default=REALISM_MINIMAL,
        choices=[REALISM_MINIMAL, REALISM_MODERATE, REALISM_HIGH],
        metavar="{0,1,2}",
        help=(
            "environment realism level: "
            "0=minimal (default), "
            "1=moderate (random stack, PEB/TEB stubs), "
            "2=high (full PEB/TEB, heap, entropy)"
        ),
    )
    real_group.add_argument(
        "--stack-size", type=int, default=int(0.5 * MEGABYTE),
        metavar="BYTES",
        help="stack size in bytes (default: 524288 = 512 KB; max recommended: 2097152 = 2 MB)",
    )
    real_group.add_argument(
        "--repmax", type=int, default=256, metavar="N",
        help="max REP-prefix iterations per step (default: 256; 0=unlimited)",
    )

    # crash handling
    crash_group = parser.add_argument_group("crash handling")
    crash_group.add_argument(
        "--crash-mode", default=CRASH_ROLLBACK,
        choices=[CRASH_ROLLBACK, CRASH_PARTIAL, CRASH_CONTINUE],
        help=(
            "crash recovery strategy: "
            f"'{CRASH_ROLLBACK}'=restore full snapshot (default), "
            f"'{CRASH_PARTIAL}'=keep memory writes/reset registers, "
            f"'{CRASH_CONTINUE}'=log and keep going"
        ),
    )

    # output
    out_group = parser.add_argument_group("output")
    out_group.add_argument("--json-output", action="store_true",
                           help="emit a JSON summary after emulation")
    out_group.add_argument("--interactive", action="store_true",
                           help="pause for input before each step (REPL-like)")

    return parser
