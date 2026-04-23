from __future__ import annotations

from dataclasses import dataclass, field
import struct
from typing import Callable, Dict, List, Optional

from unicorn import UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE
from unicorn.arm64_const import *


PAGE_SIZE = 0x1000

MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_MAIN = 0x80000028

CPU_TYPE_ARM64 = 0x0100000C

S_SYMBOL_STUBS = 0x8
S_LAZY_SYMBOL_POINTERS = 0x7
S_NON_LAZY_SYMBOL_POINTERS = 0x6
INDIRECT_SYMBOL_ABS = 0x40000000
INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_RESERVED = 0xFFFFFFFF


def align_down(value: int, alignment: int = PAGE_SIZE) -> int:
    return value & ~(alignment - 1)


def align_up(value: int, alignment: int = PAGE_SIZE) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def vm_prot_to_uc(perms: int) -> int:
    result = 0
    if perms & 0x1:
        result |= UC_PROT_READ
    if perms & 0x2:
        result |= UC_PROT_WRITE
    if perms & 0x4:
        result |= UC_PROT_EXEC
    return result or UC_PROT_READ


@dataclass
class MachOSection:
    sectname: str
    segname: str
    addr: int
    size: int
    offset: int
    align: int
    reloff: int
    nreloc: int
    flags: int
    reserved1: int
    reserved2: int
    reserved3: int


@dataclass
class MachOSegment:
    segname: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    nsects: int
    flags: int
    sections: List[MachOSection] = field(default_factory=list)


@dataclass
class MachOImage:
    path: str
    data: bytes
    segments: List[MachOSegment]
    entryoff: int
    entry_addr: Optional[int]
    symoff: Optional[int]
    nsyms: Optional[int]
    stroff: Optional[int]
    strsize: Optional[int]
    indirectsymoff: Optional[int]
    nindirectsyms: Optional[int]
    mod_init_funcs: List[int]

    @property
    def slide(self) -> int:
        preferred_bases = [seg.vmaddr - seg.fileoff for seg in self.segments if seg.filesize > 0]
        if not preferred_bases:
            return 0
        return min(preferred_bases)

    def map_into(self, mu) -> None:
        mapped_ranges: List[tuple[int, int]] = []

        for segment in self.segments:
            if segment.vmsize == 0 or segment.segname == "__PAGEZERO":
                continue

            map_start = align_down(segment.vmaddr)
            map_end = align_up(segment.vmaddr + segment.vmsize)
            map_size = map_end - map_start
            map_prot = vm_prot_to_uc(segment.initprot)

            if segment.segname != "__TEXT":
                map_prot |= UC_PROT_WRITE

            if all(not (start <= map_start < end or start < map_end <= end or map_start <= start < map_end) for start, end in mapped_ranges):
                mu.mem_map(map_start, map_size, map_prot)
                mapped_ranges.append((map_start, map_end))

            if segment.filesize > 0:
                file_data = self.data[segment.fileoff : segment.fileoff + segment.filesize]
                mu.mem_write(segment.vmaddr, file_data)

    def resolve_entry(self) -> int:
        if self.entry_addr is not None:
            return self.entry_addr
        return self.slide + self.entryoff


@dataclass
class StubTarget:
    symbol: str
    stub_addr: int
    stub_size: int


@dataclass
class SymbolBridge:
    symbol: str
    address: int


class MachOLoader:
    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as handle:
            self.data = handle.read()
        self.image = self._parse()
        self.stubs: Dict[int, StubTarget] = self._build_stub_map()
        self.bridges: Dict[int, SymbolBridge] = {}
        self.symbol_bridge_by_name: Dict[str, int] = {}
        self.heap_base = 0x6000000
        self.heap_next = self.heap_base
        self.handlers: Dict[str, Callable] = self._default_handlers()

    def _parse(self) -> MachOImage:
        self.data = self._select_slice(self.data)
        magic = struct.unpack_from("<I", self.data, 0)[0]
        if magic not in {MH_MAGIC_64, MH_CIGAM_64}:
            raise ValueError(f"Unsupported Mach-O magic: {hex(magic)}")

        endian = "<" if magic == MH_MAGIC_64 else ">"
        _, _, _, _, ncmds, _, _, _ = struct.unpack_from(endian + "IiiIIIII", self.data, 0)
        offset = 32

        segments: List[MachOSegment] = []
        entryoff = 0
        entry_addr: Optional[int] = None
        symoff = nsyms = stroff = strsize = None
        indirectsymoff = nindirectsyms = None
        mod_init_funcs: List[int] = []

        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from(endian + "II", self.data, offset)

            if cmd == LC_SEGMENT_64:
                segname_raw, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack_from(
                    endian + "16sQQQQiiII", self.data, offset + 8
                )
                segname = segname_raw.rstrip(b"\x00").decode("ascii", "ignore")
                section_offset = offset + 72
                sections: List[MachOSection] = []

                for _section_index in range(nsects):
                    section_data = struct.unpack_from(endian + "16s16sQQIIIIIIII", self.data, section_offset)
                    sectname_raw, segname2_raw, addr, size, sec_offset, align, reloff, nreloc, sec_flags, reserved1, reserved2, reserved3 = section_data
                    sections.append(
                        MachOSection(
                            sectname=sectname_raw.rstrip(b"\x00").decode("ascii", "ignore"),
                            segname=segname2_raw.rstrip(b"\x00").decode("ascii", "ignore"),
                            addr=addr,
                            size=size,
                            offset=sec_offset,
                            align=align,
                            reloff=reloff,
                            nreloc=nreloc,
                            flags=sec_flags,
                            reserved1=reserved1,
                            reserved2=reserved2,
                            reserved3=reserved3,
                        )
                    )

                    if sections[-1].sectname == "__mod_init_func":
                        init_count = size // 8
                        for idx in range(init_count):
                            (func_ptr,) = struct.unpack_from("<Q", self.data, sec_offset + idx * 8)
                            if func_ptr:
                                mod_init_funcs.append(func_ptr)

                    section_offset += 80

                segments.append(
                    MachOSegment(
                        segname=segname,
                        vmaddr=vmaddr,
                        vmsize=vmsize,
                        fileoff=fileoff,
                        filesize=filesize,
                        maxprot=maxprot,
                        initprot=initprot,
                        nsects=nsects,
                        flags=flags,
                        sections=sections,
                    )
                )

            elif cmd == LC_MAIN:
                entryoff, _stacksize = struct.unpack_from(endian + "QQ", self.data, offset + 8)

            elif cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = struct.unpack_from(endian + "IIII", self.data, offset + 8)

            elif cmd == LC_DYSYMTAB:
                fields = struct.unpack_from(endian + "IIIIIIIIIIIIIIIIII", self.data, offset + 8)
                indirectsymoff = fields[12]
                nindirectsyms = fields[13]

            offset += cmdsize

        if entryoff or entry_addr is None:
            entry_addr = self._entry_address_from_slide(segments, entryoff)

        return MachOImage(
            path=self.path,
            data=self.data,
            segments=segments,
            entryoff=entryoff,
            entry_addr=entry_addr,
            symoff=symoff,
            nsyms=nsyms,
            stroff=stroff,
            strsize=strsize,
            indirectsymoff=indirectsymoff,
            nindirectsyms=nindirectsyms,
            mod_init_funcs=mod_init_funcs,
        )

    def _select_slice(self, data: bytes) -> bytes:
        magic_be = struct.unpack_from(">I", data, 0)[0]
        if magic_be == FAT_MAGIC:
            return self._select_fat_slice(data, ">")

        magic_le = struct.unpack_from("<I", data, 0)[0]
        if magic_le == FAT_CIGAM:
            return self._select_fat_slice(data, "<")

        return data

    def _select_fat_slice(self, data: bytes, endian: str) -> bytes:
        nfat_arch = struct.unpack_from(endian + "I", data, 4)[0]
        offset = 8
        fallback: Optional[bytes] = None

        for _ in range(nfat_arch):
            cputype, cpusubtype, arch_offset, size, align = struct.unpack_from(endian + "IIIII", data, offset)
            slice_data = data[arch_offset : arch_offset + size]
            if cputype == CPU_TYPE_ARM64:
                return slice_data
            if fallback is None and slice_data:
                fallback = slice_data
            offset += 20

        if fallback is not None:
            return fallback

        raise ValueError("Unable to locate a usable Mach-O slice in fat binary")

    def _entry_address_from_slide(self, segments: List[MachOSegment], entryoff: int) -> int:
        text_candidates = [seg.vmaddr - seg.fileoff for seg in segments if seg.segname == "__TEXT"]
        if text_candidates:
            return text_candidates[0] + entryoff

        preferred_bases = [seg.vmaddr - seg.fileoff for seg in segments if seg.filesize > 0]
        if preferred_bases:
            return min(preferred_bases) + entryoff

        return entryoff

    def _build_symbol_table(self) -> List[Optional[str]]:
        if self.image.symoff is None or self.image.nsyms is None or self.image.stroff is None:
            return []

        names: List[Optional[str]] = []
        for index in range(self.image.nsyms):
            entry_off = self.image.symoff + index * 16
            n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from("<IBBHQ", self.data, entry_off)
            if n_strx == 0:
                names.append(None)
                continue

            string_start = self.image.stroff + n_strx
            if string_start >= len(self.data):
                names.append(None)
                continue

            string_end = self.data.find(b"\x00", string_start)
            if string_end < 0:
                string_end = len(self.data)
            names.append(self.data[string_start:string_end].decode("utf-8", "ignore"))

        return names

    def _build_indirect_table(self) -> List[int]:
        if self.image.indirectsymoff is None or self.image.nindirectsyms is None:
            return []

        indirect: List[int] = []
        for index in range(self.image.nindirectsyms):
            (symbol_index,) = struct.unpack_from("<I", self.data, self.image.indirectsymoff + index * 4)
            indirect.append(symbol_index)
        return indirect

    def _build_stub_map(self) -> Dict[int, StubTarget]:
        symbol_names = self._build_symbol_table()
        indirect_table = self._build_indirect_table()
        stub_map: Dict[int, StubTarget] = {}

        for segment in self.image.segments:
            for section in segment.sections:
                is_stub_section = section.sectname == "__stubs" or (section.flags & 0xFF) == S_SYMBOL_STUBS
                if not is_stub_section or section.reserved2 == 0:
                    continue

                stub_size = section.reserved2
                stub_count = section.size // stub_size

                for index in range(stub_count):
                    indirect_index = section.reserved1 + index
                    if indirect_index >= len(indirect_table):
                        continue

                    symbol_index = indirect_table[indirect_index]
                    if symbol_index in {INDIRECT_SYMBOL_ABS, INDIRECT_SYMBOL_LOCAL, INDIRECT_SYMBOL_RESERVED}:
                        continue

                    if symbol_index >= len(symbol_names):
                        continue

                    symbol_name = symbol_names[symbol_index]
                    if not symbol_name:
                        continue

                    stub_addr = section.addr + index * stub_size
                    stub_map[stub_addr] = StubTarget(symbol=symbol_name, stub_addr=stub_addr, stub_size=stub_size)

        return stub_map

    def _build_symbol_pointer_bindings(self) -> List[tuple[int, str]]:
        symbol_names = self._build_symbol_table()
        indirect_table = self._build_indirect_table()
        bindings: List[tuple[int, str]] = []

        for segment in self.image.segments:
            for section in segment.sections:
                section_type = section.flags & 0xFF
                if section_type not in {S_LAZY_SYMBOL_POINTERS, S_NON_LAZY_SYMBOL_POINTERS}:
                    continue

                pointer_size = 8
                pointer_count = section.size // pointer_size
                for index in range(pointer_count):
                    indirect_index = section.reserved1 + index
                    if indirect_index >= len(indirect_table):
                        continue

                    symbol_index = indirect_table[indirect_index]
                    if symbol_index in {INDIRECT_SYMBOL_ABS, INDIRECT_SYMBOL_LOCAL, INDIRECT_SYMBOL_RESERVED}:
                        continue
                    if symbol_index >= len(symbol_names):
                        continue

                    symbol_name = symbol_names[symbol_index]
                    if not symbol_name:
                        continue

                    bindings.append((section.addr + index * pointer_size, symbol_name))

        return bindings

    def bind_symbol_pointers(self, mu, bridge_base: int = 0x5000000) -> None:
        bindings = self._build_symbol_pointer_bindings()
        if not bindings:
            return

        bridge_size = align_up(max(1, len(bindings)) * 0x20)
        mu.mem_map(bridge_base, bridge_size, UC_PROT_READ | UC_PROT_EXEC)
        mu.mem_write(bridge_base, b"\xc0\x03\x5f\xd6" * (bridge_size // 4))

        next_bridge = bridge_base
        for pointer_addr, symbol_name in bindings:
            handler_address = self.symbol_bridge_by_name.get(symbol_name)
            if handler_address is None:
                handler_address = next_bridge
                self.symbol_bridge_by_name[symbol_name] = handler_address
                self.bridges[handler_address] = SymbolBridge(symbol=symbol_name, address=handler_address)
                next_bridge += 0x20

            print(f"[Unbound] bind {symbol_name} -> {hex(handler_address)} at {hex(pointer_addr)}")

            mu.mem_write(pointer_addr, struct.pack("<Q", handler_address))

    def _default_handlers(self) -> Dict[str, Callable]:
        def return_zero(_mu, _state):
            return 0

        def return_self(mu, _state):
            return mu.reg_read(UC_ARM64_REG_X0)

        def allocate_heap_block(mu, size: int, label: str) -> int:
            alloc_size = align_up(max(0x20, size))
            address = self.heap_next
            mu.mem_map(address, alloc_size, UC_PROT_READ | UC_PROT_WRITE)
            mu.mem_write(address, b"\x00" * alloc_size)
            self.heap_next += alloc_size
            print(f"[Unbound] heap alloc {label} size={hex(alloc_size)} -> {hex(address)}")
            return address

        def swift_generic(mu, state):
            print(f"[Unbound] swift shim {state.symbol}")
            if "allocObject" in state.symbol or "AllocObject" in state.symbol:
                return allocate_heap_block(mu, 0x100, state.symbol)
            if "release" in state.symbol or "Retain" in state.symbol:
                return mu.reg_read(UC_ARM64_REG_X0)
            return 0

        def dispatch_once(mu, state):
            token = mu.reg_read(UC_ARM64_REG_X0)
            func = mu.reg_read(UC_ARM64_REG_X1)
            print(f"[Unbound] dispatch_once -> token={hex(token)} func={hex(func)} ({state.symbol})")
            return 0

        def objc_runtime_passthrough(mu, state):
            arg0 = mu.reg_read(UC_ARM64_REG_X0)
            arg1 = mu.reg_read(UC_ARM64_REG_X1)
            print(f"[Unbound] objc runtime shim {state.symbol} x0={hex(arg0)} x1={hex(arg1)}")
            return arg0

        def cf_passthrough(mu, state):
            arg0 = mu.reg_read(UC_ARM64_REG_X0)
            print(f"[Unbound] CoreFoundation shim {state.symbol} x0={hex(arg0)}")
            return arg0

        def objc_msg_send(mu, state):
            receiver = mu.reg_read(UC_ARM64_REG_X0)
            selector = mu.reg_read(UC_ARM64_REG_X1)
            print(f"[Unbound] objc_msgSend -> receiver={hex(receiver)} selector={hex(selector)} ({state.symbol})")
            return receiver

        def objc_alloc_with_zone(mu, state):
            cls = mu.reg_read(UC_ARM64_REG_X0)
            zone = mu.reg_read(UC_ARM64_REG_X1)
            print(f"[Unbound] objc_allocWithZone -> class={hex(cls)} zone={hex(zone)} ({state.symbol})")
            return allocate_heap_block(mu, 0x100, state.symbol)

        def objc_autorelease_pool_push(_mu, state):
            print(f"[Unbound] autorelease pool push ({state.symbol})")
            return 0x1

        def objc_autorelease_pool_pop(_mu, state):
            print(f"[Unbound] autorelease pool pop ({state.symbol})")
            return 0

        def objc_retain_return_value(mu, state):
            value = mu.reg_read(UC_ARM64_REG_X0)
            print(f"[Unbound] objc retain/autorelease shim {state.symbol} -> {hex(value)}")
            return value

        def os_log_with_type(_mu, state):
            print(f"[Unbound] os_log ignored for {state.symbol}")
            return 0

        def ui_application_main(mu, state):
            argc = mu.reg_read(UC_ARM64_REG_X0)
            argv = mu.reg_read(UC_ARM64_REG_X1)
            principal = mu.reg_read(UC_ARM64_REG_X2)
            delegate = mu.reg_read(UC_ARM64_REG_X3)
            print(
                f"[Unbound] UIApplicationMain argc={argc} argv={hex(argv)} principal={hex(principal)} delegate={hex(delegate)}"
            )
            return 0

        def nsstring_from_class(mu, state):
            cls = mu.reg_read(UC_ARM64_REG_X0)
            print(f"[Unbound] NSStringFromClass -> {hex(cls)} ({state.symbol})")
            return allocate_heap_block(mu, 0x100, state.symbol)

        handlers = {
            "_objc_msgSend": objc_msg_send,
            "objc_msgSend": objc_msg_send,
            "_objc_msgSendSuper2": objc_msg_send,
            "objc_msgSendSuper2": objc_msg_send,
            "_objc_msgSendSuper": objc_msg_send,
            "objc_msgSendSuper": objc_msg_send,
            "_objc_autoreleasePoolPush": objc_autorelease_pool_push,
            "objc_autoreleasePoolPush": objc_autorelease_pool_push,
            "_objc_autoreleasePoolPop": objc_autorelease_pool_pop,
            "objc_autoreleasePoolPop": objc_autorelease_pool_pop,
            "_objc_retainAutoreleasedReturnValue": objc_retain_return_value,
            "objc_retainAutoreleasedReturnValue": objc_retain_return_value,
            "_objc_retain": objc_retain_return_value,
            "objc_retain": objc_retain_return_value,
            "_objc_release": return_zero,
            "objc_release": return_zero,
            "_objc_autorelease": return_self,
            "objc_autorelease": return_self,
            "_dispatch_once": dispatch_once,
            "dispatch_once": dispatch_once,
            "_dispatch_once_f": dispatch_once,
            "dispatch_once_f": dispatch_once,
            "_dispatch_async": return_zero,
            "dispatch_async": return_zero,
            "_dispatch_get_main_queue": return_zero,
            "dispatch_get_main_queue": return_zero,
            "_dispatch_get_global_queue": return_zero,
            "dispatch_get_global_queue": return_zero,
            "_dispatch_main": return_zero,
            "dispatch_main": return_zero,
            "_dispatch_semaphore_create": return_zero,
            "dispatch_semaphore_create": return_zero,
            "_dispatch_semaphore_signal": return_zero,
            "dispatch_semaphore_signal": return_zero,
            "_dispatch_semaphore_wait": return_zero,
            "dispatch_semaphore_wait": return_zero,
            "_objc_storeStrong": return_self,
            "objc_storeStrong": return_self,
            "_objc_init": return_zero,
            "objc_init": return_zero,
            "_CFRelease": cf_passthrough,
            "CFRelease": cf_passthrough,
            "_CFRetain": cf_passthrough,
            "CFRetain": cf_passthrough,
            "_CFStringCreateWithCString": cf_passthrough,
            "CFStringCreateWithCString": cf_passthrough,
            "_CFStringCreateCopy": cf_passthrough,
            "CFStringCreateCopy": cf_passthrough,
            "_CFGetTypeID": return_zero,
            "CFGetTypeID": return_zero,
            "_os_log_with_type": os_log_with_type,
            "os_log_with_type": os_log_with_type,
            "_NSLog": os_log_with_type,
            "NSLog": os_log_with_type,
            "_UIApplicationMain": ui_application_main,
            "UIApplicationMain": ui_application_main,
            "_NSStringFromClass": nsstring_from_class,
            "NSStringFromClass": nsstring_from_class,
            "_objc_allocWithZone": objc_alloc_with_zone,
            "objc_allocWithZone": objc_alloc_with_zone,
            "_objc_alloc": objc_alloc_with_zone,
            "objc_alloc": objc_alloc_with_zone,
            "swift": swift_generic,
            "__swift": swift_generic,
            "__T": swift_generic,
            "_swift_allocObject": swift_generic,
            "swift_allocObject": swift_generic,
            "_swift_getExistentialTypeMetadata": swift_generic,
            "swift_getExistentialTypeMetadata": swift_generic,
            "_swift_getInitializedObjCClass": swift_generic,
            "swift_getInitializedObjCClass": swift_generic,
            "_swift_release": swift_generic,
            "swift_release": swift_generic,
            "_swift_reportFatalErrorsToDebugger": swift_generic,
            "swift_reportFatalErrorsToDebugger": swift_generic,
            "_swift_slowAlloc": swift_generic,
            "swift_slowAlloc": swift_generic,
            "_swift_slowDealloc": swift_generic,
            "swift_slowDealloc": swift_generic,
            "_swift_beginAccess": swift_generic,
            "swift_beginAccess": swift_generic,
            "_swift_endAccess": swift_generic,
            "swift_endAccess": swift_generic,
            "_swift_bridgeObjectRelease": swift_generic,
            "swift_bridgeObjectRelease": swift_generic,
            "_swift_bridgeObjectRetain": swift_generic,
            "swift_bridgeObjectRetain": swift_generic,
            "_swift_deallocClassInstance": swift_generic,
            "swift_deallocClassInstance": swift_generic,
            "_swift_getForeignTypeMetadata": swift_generic,
            "swift_getForeignTypeMetadata": swift_generic,
            "_swift_getObjCClassMetadata": swift_generic,
            "swift_getObjCClassMetadata": swift_generic,
            "_swift_unknownRelease": swift_generic,
            "swift_unknownRelease": swift_generic,
            "_swift_unknownRetain": swift_generic,
            "swift_unknownRetain": swift_generic,
            "_swift_unknownWeakAssign": swift_generic,
            "swift_unknownWeakAssign": swift_generic,
            "_swift_unknownWeakDestroy": swift_generic,
            "swift_unknownWeakDestroy": swift_generic,
            "_swift_unknownWeakInit": swift_generic,
            "swift_unknownWeakInit": swift_generic,
            "_swift_unknownWeakLoadStrong": swift_generic,
            "swift_unknownWeakLoadStrong": swift_generic,
            "_dyld_stub_binder": return_zero,
            "dyld_stub_binder": return_zero,
        }

        return handlers

    def get_entry_point(self) -> int:
        return self.image.resolve_entry()

    def load(self, mu) -> None:
        self.image.map_into(mu)

    def call_initializers(self, mu, call_helper: Callable[[int], None]) -> None:
        for initializer in self.image.mod_init_funcs:
            call_helper(initializer)

    def resolve_stub(self, address: int) -> Optional[StubTarget]:
        return self.stubs.get(address)

    def dispatch_stub(self, mu, address: int) -> bool:
        stub = self.resolve_stub(address)
        if stub is None:
            return False

        handler = self._lookup_handler(stub.symbol)
        if handler is None:
            print(f"[Unbound] unresolved stub {stub.symbol} at {hex(address)}")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        else:
            result = handler(mu, stub)
            if result is not None:
                mu.reg_write(UC_ARM64_REG_X0, result)

        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_X30))
        return True

    def dispatch_bridge(self, mu, address: int) -> bool:
        bridge = self.bridges.get(address)
        if bridge is None:
            return False

        handler = self._lookup_handler(bridge.symbol)
        if handler is None:
            print(f"[Unbound] unresolved bridge {bridge.symbol} at {hex(address)}")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        else:
            result = handler(mu, bridge)
            if result is not None:
                mu.reg_write(UC_ARM64_REG_X0, result)

        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_X30))
        return True

    def _lookup_handler(self, symbol: str) -> Optional[Callable]:
        if symbol in self.handlers:
            return self.handlers[symbol]

        stripped = symbol.lstrip("_")
        if stripped in self.handlers:
            return self.handlers[stripped]

        if stripped.startswith("swift_") or stripped.startswith("__swift_") or stripped.startswith("__T"):
            return self.handlers.get("swift")

        return None
