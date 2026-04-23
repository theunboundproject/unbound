from __future__ import annotations

import os

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import *
from unicorn.arm64_const import *

from mach_o_loader import MachOLoader


STACK_ADDR = 0x2000000
STACK_SIZE = 2 * 1024 * 1024
SENTINEL_RET_ADDR = 0x4000000
RUNLOOP_ADDR = 0x7000000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BINARY = os.path.join(BASE_DIR, "Payload", "calculator.app", "calculator")
MAIN_EXECUTION_BUDGET = 5000000
TRACE_INSTRUCTION_LIMIT = 400

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
_RUNLOOP_LOGGED = False
_TRACE_COUNT = 0


def hook_mem_invalid(mu, access, address, size, value, user_data):
    pc = mu.reg_read(UC_ARM64_REG_PC)
    lr = mu.reg_read(UC_ARM64_REG_X30)
    page_base = address & ~0xFFF

    if access == UC_MEM_WRITE_PROT:
        try:
            mu.mem_protect(page_base, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
            return True
        except UcError:
            mu.emu_stop()
            return False

    if access == UC_MEM_FETCH_UNMAPPED:
        if address == 0 or lr == 0:
            print("\n[Unbound] execution reached an unmapped return path. Stopping.")
            mu.emu_stop()
            return False

        mu.reg_write(UC_ARM64_REG_PC, SENTINEL_RET_ADDR)
        return True

    if access in (UC_MEM_READ_UNMAPPED, UC_MEM_WRITE_UNMAPPED):
        try:
            mu.mem_map(page_base, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
            return True
        except UcError:
            mu.reg_write(UC_ARM64_REG_PC, pc + 4)
            return True

    mu.reg_write(UC_ARM64_REG_PC, pc + 4)
    return True


def hook_code(loader: MachOLoader, mu, address, size, user_data):
    global _RUNLOOP_LOGGED, _TRACE_COUNT

    if address == SENTINEL_RET_ADDR:
        mu.emu_stop()
        return

    if address == RUNLOOP_ADDR:
        if not _RUNLOOP_LOGGED:
            print("[Unbound] entered synthetic UIKit run loop")
            _RUNLOOP_LOGGED = True
        return

    if loader.dispatch_bridge(mu, address):
        return

    if loader.dispatch_stub(mu, address):
        return

    if _TRACE_COUNT >= TRACE_INSTRUCTION_LIMIT:
        return

    code_bytes = mu.mem_read(address, size)
    for instruction in md.disasm(code_bytes, address):
        print(f"--- {hex(instruction.address)}: {instruction.mnemonic}\t{instruction.op_str}")
        _TRACE_COUNT += 1
        if _TRACE_COUNT >= TRACE_INSTRUCTION_LIMIT:
            break


def call_function(mu, address: int):
    saved_sp = mu.reg_read(UC_ARM64_REG_SP)
    saved_lr = mu.reg_read(UC_ARM64_REG_X30)

    mu.reg_write(UC_ARM64_REG_X30, SENTINEL_RET_ADDR)
    try:
        mu.emu_start(address, SENTINEL_RET_ADDR)
    except UcError as error:
        pc = mu.reg_read(UC_ARM64_REG_PC)
        if pc != SENTINEL_RET_ADDR:
            print(f"[Unbound] initializer at {hex(address)} stopped at {hex(pc)}: {error}")
    finally:
        mu.reg_write(UC_ARM64_REG_SP, saved_sp)
        mu.reg_write(UC_ARM64_REG_X30, saved_lr)


def run_unbound(binary_path: str = DEFAULT_BINARY):
    loader = MachOLoader(binary_path)

    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    loader.load(mu)
    loader.bind_symbol_pointers(mu)

    mu.mem_map(STACK_ADDR, STACK_SIZE)
    mu.mem_map(SENTINEL_RET_ADDR, 4096, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    mu.mem_write(SENTINEL_RET_ADDR, b"\xc0\x03\x5f\xd6")
    mu.mem_map(RUNLOOP_ADDR, 4096, UC_PROT_READ | UC_PROT_EXEC)
    mu.mem_write(RUNLOOP_ADDR, b"\x00\x00\x00\x14" * (4096 // 4))

    mu.hook_add(
        UC_HOOK_MEM_READ_UNMAPPED
        | UC_HOOK_MEM_WRITE_UNMAPPED
        | UC_HOOK_MEM_FETCH_UNMAPPED
        | UC_HOOK_MEM_WRITE_PROT,
        hook_mem_invalid,
    )
    mu.hook_add(UC_HOOK_CODE, lambda mu_, address, size, user_data: hook_code(loader, mu_, address, size, user_data))

    mu.reg_write(UC_ARM64_REG_SP, STACK_ADDR + STACK_SIZE)

    loader.call_initializers(mu, lambda func_addr: call_function(mu, func_addr))

    entry_point = loader.get_entry_point()
    print(f"🚀 Starting emulation at {hex(entry_point)} from {binary_path}\n")

    try:
        mu.emu_start(entry_point, 0xFFFFFFFFFFFFFFFF, count=MAIN_EXECUTION_BUDGET)
    except UcError as error:
        pc = mu.reg_read(UC_ARM64_REG_PC)
        if pc not in (0, SENTINEL_RET_ADDR):
            print(f"⚠️ Emulation stopped at {hex(pc)}: {error}")


if __name__ == "__main__":
    run_unbound()
