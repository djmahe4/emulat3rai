

MEGABYTE = 1024 * 1024
STACK_MEM_NAME = "[stack]"
DEFAULT_SC_BASE = 0x690000  # viv_utils default
MAX_INST_SIZE = 200
STACK_CTX = 4   # How many stack entries to show

# x64 registers to display
AMD64_REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

# eflags bit definitions
EFLAGS = [
    (0,  "CF"),   # carry
    (2,  "PF"),   # parity
    (4,  "AF"),   # auxiliary carry
    (6,  "ZF"),   # zero
    (7,  "SF"),   # sign
    (10, "DF"),   # direction
    (11, "OF"),   # overflow
]