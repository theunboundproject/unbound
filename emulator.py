from unicorn import *
from unicorn.arm64_const import *
from capstone import *
import struct

# 1. Configuration
ADDRESS = 0x1000000  
STACK_ADDR = 0x2000000 
STACK_SIZE = 2 * 1024 * 1024 

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def hook_code(mu, address, size, user_data):
    # --- UNIVERSAL INTERCEPTOR ---
    # We now look for the pattern of the "Stub Jump"
    # Most iOS external calls happen in the 0x1008000+ range in this binary
    if 0x10086e8 <= address <= 0x1008750:
        # Check if the instruction is a 'br x8' or 'ldr x8' that's about to fail
        # For now, let's just skip this whole "External Lookup" block
        # whenever we hit one of these "adrp" start points.
        
        # Current crash is at 0x1008700. Let's nudge past this whole block too.
        if address == 0x10086f8:
            print(f"\n[Unbound] 💥 INTERCEPTED: Second External Call at {hex(address)}")
            # Skip the lookup (adrp, ldr, ldr, br) - usually 16 bytes
            mu.reg_write(UC_ARM64_REG_PC, 0x1008708)
            print(f"[Unbound] Nudged PC to 0x1008708.\n")
            return

    # Standard Trace Printing
    code = mu.mem_read(address, size)
    for i in md.disasm(code, address):
        print(f"--- {hex(i.address)}: {i.mnemonic}\t{i.op_str}")

def run_unbound():
    try:
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        mu.mem_map(ADDRESS, 16 * 1024 * 1024) 
        mu.mem_map(STACK_ADDR, STACK_SIZE)

        with open("extracted_arm64.bin", "rb") as f:
            mu.mem_write(ADDRESS, f.read())

        mu.reg_write(UC_ARM64_REG_SP, STACK_ADDR + STACK_SIZE)
        mu.hook_add(UC_HOOK_CODE, hook_code)

        entry_point = ADDRESS + 0x96d8 
        print(f"🚀 Starting emulation at {hex(entry_point)}...\n")
        
        mu.emu_start(entry_point, 0)

    except UcError as e:
        pc = mu.reg_read(UC_ARM64_REG_PC)
        print(f"\n🛑 HALTED: {e} at {hex(pc)}")

if __name__ == "__main__":
    run_unbound()