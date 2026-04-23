from unicorn import *
from unicorn.arm64_const import *
from capstone import *
import struct

# --- Configuration ---
ADDRESS         = 0x1000000  
STACK_ADDR      = 0x2000000 
STACK_SIZE      = 2 * 1024 * 1024 
DUMMY_FUNC_ADDR = 0x4000000 
ENTRY_OFFSET    = 0x96d8
STUB_LOOP_ADDR  = 0x10086f0 

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def hook_mem_invalid(mu, access, address, size, value, user_data):
    pc = mu.reg_read(UC_ARM64_REG_PC)
    lr = mu.reg_read(UC_ARM64_REG_X30)
    
    if access == UC_MEM_FETCH_UNMAPPED:
        # Graceful Exit: Check if we finished the main function
        if address == 0:
            if lr == 0:
                print("\n[Unbound] 🏁 SUCCESS: Main function reached final return. Stopping.")
                mu.emu_stop()
                return False
            else:
                # Attempt recovery if the Link Register has a valid return path
                mu.reg_write(UC_ARM64_REG_PC, lr)
                return True

        # Redirect any other unmapped fetches (library calls) to our Safe Zone
        mu.reg_write(UC_ARM64_REG_PC, DUMMY_FUNC_ADDR)
        return True

    # Handle unmapped Data Reads/Writes by skipping the instruction
    mu.reg_write(UC_ARM64_REG_PC, pc + 4)
    return True

def hook_code(mu, address, size, user_data):
    # Specialized fix for the infinite LDR loop stub
    if address == STUB_LOOP_ADDR:
        mu.reg_write(UC_ARM64_REG_X8, DUMMY_FUNC_ADDR)
        mu.reg_write(UC_ARM64_REG_PC, address + 4)
        return

    # Don't log instructions inside the Safe Zone to keep output clean
    if address == DUMMY_FUNC_ADDR:
        return

    # Instruction Tracer
    code_bytes = mu.mem_read(address, size)
    for i in md.disasm(code_bytes, address):
        print(f"--- {hex(i.address)}: {i.mnemonic}\t{i.op_str}")

def run_unbound():
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    
    # Setup Memory Map
    mu.mem_map(ADDRESS, 16 * 1024 * 1024) 
    mu.mem_map(STACK_ADDR, STACK_SIZE)
    mu.mem_map(DUMMY_FUNC_ADDR, 4096)
    
    # Initialize Safe Zone with a 'RET' instruction (\xc0\x03\x5f\xd6)
    mu.mem_write(DUMMY_FUNC_ADDR, b'\xc0\x03\x5f\xd6')

    try:
        with open("code.bin", "rb") as f:
            mu.mem_write(ADDRESS, f.read())
    except FileNotFoundError:
        print("❌ Error: 'code.bin' not found.")
        return

    # --- Import Table Simulation ---
    # We pre-fill these specific memory slots with the Safe Zone address
    # so that 'br x16' style jumps land safely in our RET handler.
    VOID_SLOTS = [
        0x100c090, 
        0x100c000 + 0x50, 
        0x100c198, 
        0x100c098 
    ] 
    
    for slot in VOID_SLOTS:
        try:
            mu.mem_write(slot, struct.pack('<Q', DUMMY_FUNC_ADDR))
        except Exception:
            pass

    # Register Hooks
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | 
                UC_HOOK_MEM_WRITE_UNMAPPED | 
                UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid)
    mu.hook_add(UC_HOOK_CODE, hook_code)
    
    # Initialize CPU State
    mu.reg_write(UC_ARM64_REG_SP, STACK_ADDR + STACK_SIZE)
    current_pc = ADDRESS + ENTRY_OFFSET
    
    print(f"🚀 Starting emulation at {hex(current_pc)}...\n")

    try:
        # Start the engine
        mu.emu_start(current_pc, 0xFFFFFFFFFFFFFFFF)
    except UcError as e:
        pc = mu.reg_read(UC_ARM64_REG_PC)
        if pc != 0:
            print(f"⚠️ Emulation stopped at {hex(pc)}: {e}")

if __name__ == "__main__":
    run_unbound()