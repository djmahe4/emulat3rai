import os
import sys
from rich import print as rprint

from src.pe import *
from src.misc import *
from src.cliargs import build_parser
from src.shellcode import emulate_shellcode
from src.config import EmulatorConfig
from src.analyzer import list_functions

def main():
    parser = build_parser()
    args = parser.parse_args()
    banner()

    cfg = EmulatorConfig.from_args(args)

    # shellcode from inline hex
    if args.sc_hex:
        rprint("[[green]*[/green]] Parsing Hex Codes....")
        sc_bytes = parse_hex_string(args.sc_hex.strip())
        cfg.sc_base         = args.base
        cfg.sc_entry_offset = args.entry
        cfg.stop_on_ret     = False
        emulate_shellcode(sc_bytes, cfg=cfg)
        return

    if args.shellcode:
        rprint("[[green]*[/green]] Parsing Shellcode....")
        sc_bytes = load_shellcode_bytes(args.shellcode, args.hex)
        cfg.sc_base         = args.base
        cfg.sc_entry_offset = args.entry
        cfg.stop_on_ret     = False
        emulate_shellcode(sc_bytes, cfg=cfg)
        return

    if not args.pe:
        parser.print_help()
        sys.exit(1)

    if args.list:
        pe = os.path.abspath(args.pe)
        rprint(f"[[cyan]*[/cyan]] Listing functions from PE: [magenta]{pe}[/magenta]")
        list_functions(pe)
        return

    pe = os.path.abspath(args.pe)
    emulate_pe(pe, args.va, args.max,
               follow_calls=args.follow_calls, follow_va=args.follow_va,
               stack_context=args.stack_context, cfg=cfg)


if __name__ == '__main__':
    main()