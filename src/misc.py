from rich import print as rprint
import logging

def banner():
    rprint(r"""
███████╗███╗   ███╗██╗   ██╗██╗      █████╗ ████████╗██████╗ ██████╗  █████╗ ██╗
██╔════╝████╗ ████║██║   ██║██║     ██╔══██╗╚══██╔══╝╚════██╗██╔══██╗██╔══██╗██║
█████╗  ██╔████╔██║██║   ██║██║     ███████║   ██║    █████╔╝██████╔╝███████║██║
██╔══╝  ██║╚██╔╝██║██║   ██║██║     ██╔══██║   ██║    ╚═══██╗██╔══██╗██╔══██║██║
███████╗██║ ╚═╝ ██║╚██████╔╝███████╗██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║██║
╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝

                         modular x64 instruction-level emulator
                                                 [yellow]@djmahe4 / whokilleddb[/yellow]""")

def parse_hex_string(hex_str: str) -> bytes:
    """Parse a hex string like '31c0c3' or '\\x31\\xc0\\xc3'."""
    cleaned = hex_str.replace("\\x", "").replace("0x", "").replace(" ", "")
    return bytes.fromhex(cleaned)


def suppress_viv_logging():
    for name in ("vivisect", "vivisect.base", "vivisect.impemu", "vtrace", "envi", "envi.codeflow"):
        logging.getLogger(name).setLevel(logging.ERROR)

