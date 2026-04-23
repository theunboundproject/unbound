from unicorn import *
from unicorn.arm64_const import *
from capstone import *
import struct

# 1. Configuration
ADDRESS = 0x1000000  
STACK_ADDR = 0x2000000 
STACK_SIZE = 2 * 1024 * 1024 

# Initialize Disassembler for ARM64
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def hook_code(mu, address, size, user_data):
    # Read the bytes at the current instruction
    code = mu.mem_read(address, size)
    # Disassemble the bytes so we can read the "English" version of the code
    for i in md.disasm(code, address):
        print(f"--- {hex(i.address)}: {i.mnemonic}\t{i.op_str}")

def run_unbound():
    try:
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        # 2. Map Memory
        # We increase mapping to 16MB to ensure the full binary and data fit
        mu.mem_map(ADDRESS, 16 * 1024 * 1024) 
        mu.mem_map(STACK_ADDR, STACK_SIZE)

        # 3. Load the FULL Binary
        with open("extracted_arm64.bin", "rb") as f:
            full_binary = f.read()
            mu.mem_write(ADDRESS, full_binary)
            print(f"✅ Loaded {len(full_binary)} bytes into memory.")

        # 4. Setup Stack & Hook
        mu.reg_write(UC_ARM64_REG_SP, STACK_ADDR + STACK_SIZE)
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # 5. Start Emulation (Entry Point: 0x96d8)
        entry_point = ADDRESS + 0x96d8 
        print(f"🚀 Starting emulation at {hex(entry_point)}...\n")
        
        # Run until we hit an error
        mu.emu_start(entry_point, entry_point + 0x10000)

    except UcError as e:
        print(f"\n🛑 EMULATION HALTED: {e}")
        pc = mu.reg_read(UC_ARM64_REG_PC)
        
        # Read the failing instruction bytes
        try:
            instruction_bytes = mu.mem_read(pc, 4)
            for i in md.disasm(instruction_bytes, pc):
                print(f"❌ FAILING INSTRUCTION: {i.mnemonic}\t{i.op_str}")
        except:
            print("❌ Could not read failing instruction.")

        print("-" * 30)
        print(f"📍 PC: {hex(pc)}")
        print(f"📦 X0: {hex(mu.reg_read(UC_ARM64_REG_X0))}")
        print(f"📦 X1: {hex(mu.reg_read(UC_ARM64_REG_X1))}")
        print("-" * 30)

if __name__ == "__main__":
    run_unbound()