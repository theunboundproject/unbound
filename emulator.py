from unicorn import *
from unicorn.arm64_const import *
from capstone import *
import struct
import sys

# 1. Configuration
ADDRESS = 0x1000000  
STACK_ADDR = 0x2000000 
STACK_SIZE = 2 * 1024 * 1024 
FAKE_LIB_ADDR = 0x3000000 

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

# This function runs when the CPU hits our Fake Library
def unbound_stub_objc_msgSend(mu, address, size, user_data):
    print("\n[Unbound] 💥 INTERCEPTED: objc_msgSend")
    
    # Read registers to see what the app is doing
    x0 = mu.reg_read(UC_ARM64_REG_X0)
    x1 = mu.reg_read(UC_ARM64_REG_X1)
    lr = mu.reg_read(UC_ARM64_REG_X30) # Link Register (where we return to)
    
    print(f"[Unbound] Object: {hex(x0)} | Selector (Command): {hex(x1)}")
    print(f"[Unbound] Will return to: {hex(lr)}")

def hook_code(mu, address, size, user_data):
    # Standard tracing
    code = mu.mem_read(address, size)
    for i in md.disasm(code, address):
        print(f"--- {hex(i.address)}: {i.mnemonic}\t{i.op_str}")

def run_unbound():
    try:
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        mu.mem_map(ADDRESS, 16 * 1024 * 1024) 
        mu.mem_map(STACK_ADDR, STACK_SIZE)
        mu.mem_map(FAKE_LIB_ADDR, 4 * 1024)

        # 2. Load Binary
        with open("extracted_arm64.bin", "rb") as f:
            mu.mem_write(ADDRESS, f.read())

        # 3. Prepare the "Fake Library"
        # We write an ARM64 'RET' instruction (0xc0035fd6) to FAKE_LIB_ADDR
        # This tells the CPU: "Go back to whoever called you."
        ret_instruction = struct.pack('<I', 0xd65f03c0) 
        mu.mem_write(FAKE_LIB_ADDR, ret_instruction)

        # 4. The "Linker" Fix-up
        patch_addr = 0x100c050
        stub_pointer = struct.pack('<Q', FAKE_LIB_ADDR)
        mu.mem_write(patch_addr, stub_pointer)
        print(f"🛠️  Patched Import Table at {hex(patch_addr)} -> {hex(FAKE_LIB_ADDR)}")

        # 5. Add Hooks
        # Hook specifically for the stub address
        mu.hook_add(UC_HOOK_CODE, unbound_stub_objc_msgSend, begin=FAKE_LIB_ADDR, end=FAKE_LIB_ADDR)
        # Hook for general tracing
        mu.hook_add(UC_HOOK_CODE, hook_code)

        mu.reg_write(UC_ARM64_REG_SP, STACK_ADDR + STACK_SIZE)

        entry_point = ADDRESS + 0x96d8 
        print(f"🚀 Starting emulation at {hex(entry_point)}...\n")
        
        mu.emu_start(entry_point, entry_point + 0x10000)

    except UcError as e:
        pc = mu.reg_read(UC_ARM64_REG_PC)
        print(f"\n🛑 HALTED: {e} at {hex(pc)}")

if __name__ == "__main__":
    run_unbound()