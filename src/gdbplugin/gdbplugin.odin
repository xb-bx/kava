package gdbplugin 
import "core:sys/unix"
import "core:fmt"
import "core:strings"
import "core:slice"
import "core:runtime"
import "kava:shared"
import "core:mem"

GDB_READER_INTERFACE_VERSION :: 1


GDBStatus :: enum u32 {
    Fail = 0,
    Success,
}
GDBObject :: struct {}
GDBSymtab :: struct {}
GDBBlock :: struct {}
GDBCoreAddr :: distinct uintptr 
GDBLineMapping :: struct {
    line: i32,
    pc: GDBCoreAddr,
}
GDBObjectOpen :: distinct proc "c" (cb: ^GDBSymbolCallbacks) -> ^GDBObject
GDBSymtabOpen :: distinct proc "c" (cb: ^GDBSymbolCallbacks, obj: ^GDBObject, file_name: cstring) -> ^GDBSymtab
GDBBlockOpen :: distinct proc "c" (cb: ^GDBSymbolCallbacks, symtab: ^GDBSymtab, parent: ^GDBBlock,  begin: GDBCoreAddr, end: GDBCoreAddr, name: cstring) -> ^GDBBlock
GDBSymtabAddLineMapping :: distinct proc "c" (cb: ^GDBSymbolCallbacks, symtab: ^GDBSymtab, nlines: i32, lines: [^]GDBLineMapping)
GDBSymtabClose :: distinct proc "c" (cb: ^GDBSymbolCallbacks, symtab: ^GDBSymtab) 
GDBObjectClose :: distinct proc "c" (cb: ^GDBSymbolCallbacks, obj: ^GDBObject) 
GDBTargetRead :: distinct proc "c" (target_mem: GDBCoreAddr, buf: [^]u8, len: i32) -> GDBStatus



@export
plugin_is_GPL_compatible :: proc "c" () -> i32 { return 0; }

target_read_cstring :: proc(target_read: GDBTargetRead, addr: rawptr, len: int) -> cstring {

    buf, err := mem.alloc(len)
    if err != .None || buf == nil {
        fmt.println(addr, len)
        if true { panic("biba") }
        return nil
    }
    target_read(transmute(GDBCoreAddr)addr, transmute([^]u8)buf, cast(i32)len)
    cstr := transmute(cstring)buf

    return cstr
}
target_read_slice :: proc($T: typeid, target_read: GDBTargetRead, ptr: rawptr, len: int) -> []T {
    buf := make([]T, len)
    err := target_read(transmute(GDBCoreAddr)ptr, transmute([^]u8)slice.as_ptr(buf), cast(i32)len * size_of(T))
    if err == .Fail {
        return nil 
    }
    return buf
}
read_info :: proc "c" (self: ^GDBReaderFuncs, cb: ^GDBSymbolCallbacks, memory: [^]u8, memory_sz: i32) -> GDBStatus {
    context = (transmute(^runtime.Context)self.priv_data)^
    symbol := (transmute(^shared.Symbol)memory)^
    obj := cb.object_open(cb)
    if obj == nil {
        if true { panic("") }
        return .Fail
    }

    filename := target_read_cstring(cb.target_read, transmute(rawptr)symbol.file, symbol.file_len) 
    if filename == nil {
        if true { panic("") }
        return .Fail
    }
    sym := cb.symtab_open(cb, obj, filename)
    if sym == nil {
        if true { panic("") }
        return .Fail
    }
    functionname := target_read_cstring(cb.target_read, transmute(rawptr)symbol.function, symbol.function_len) 
    if functionname == nil {
        if true { panic("") }
        return .Fail
    }
    block := cb->block_open(sym, nil, transmute(GDBCoreAddr)symbol.start, transmute(GDBCoreAddr)symbol.end, functionname)
    if block == nil {
        if true { panic("") }
        return .Fail
    }
    lines := target_read_slice(shared.LineMapping, cb.target_read, symbol.line_mapping, symbol.line_mapping_len)
//     defer delete(lines)
//     gdblines := make([]GDBLineMapping, len(lines))
//     for line, i in lines {
//         gdblines[i] = GDBLineMapping { line = cast(i32)line.line, pc = transmute(GDBCoreAddr)line.pc + transmute(GDBCoreAddr)symbol.start }
//     }
    for i in 0..<len(lines) {
        fmt.println((transmute([^]GDBLineMapping)slice.as_ptr(lines))[i])
    }
    cb.line_mapping_add(cb, sym, cast(i32)len(lines), transmute([^]GDBLineMapping)slice.as_ptr(lines))
    cb.symtab_close(cb, sym)
    cb.object_close(cb, obj)
    return .Success    
}
unwind :: proc "c" (self: ^GDBReaderFuncs, cb: ^GDBUnwindCallbacks) -> GDBStatus {
    return .Fail
}
destroy :: proc "c" (self: ^GDBReaderFuncs) {}
get_frame_id :: proc "c" (self: ^GDBReaderFuncs, cb: ^GDBUnwindCallbacks) -> GDBFrameId {
//     context = {}
//     panic("")
    return {}
}


funcs := GDBReaderFuncs {
    reader_version = GDB_READER_INTERFACE_VERSION,
    read = read_info,
    unwind = unwind,
    get_frame_id = get_frame_id,
    destroy = destroy,
}
ctx: runtime.Context = {}

@export
gdb_init_reader :: proc "c" () -> ^GDBReaderFuncs {
    funcs.priv_data = transmute([^]u8)&ctx 
    return &funcs
}



GDBReaderFuncs  :: struct {
    reader_version: i32,
    priv_data: [^]u8,
    read: GDBReadDebugInfo,
    unwind: GDBUnwindFrame,
    get_frame_id: GDBGetFrameId,
    destroy: GDBDestroyReader,
}
GDBSymbolCallbacks :: struct {
    object_open: GDBObjectOpen,
    symtab_open: GDBSymtabOpen,
    block_open: GDBBlockOpen,
    symtab_close: GDBSymtabClose,
    object_close: GDBObjectClose,
    line_mapping_add: GDBSymtabAddLineMapping,
    target_read: GDBTargetRead,
    priv_data: [^]u8,
}
GDBRegValueFree :: distinct proc "c" (reg_value: ^GDBRegValue);
GDBRegValue :: struct {
    size: i32,
    defined: i32,
    free: GDBRegValueFree,
    value: [1]u8,
}
GDBFrameId :: struct {
    code_address: GDBCoreAddr,
    stack_address: GDBCoreAddr,
}
GDBReg :: enum i32 {
    Rax = 0,
    Rdx,
    Rcx, 
    Rbx,
    Rsi,
    Rdi,
    Rbp,
    Rsp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Rip,
    Xmm0,
    Xmm1,
    Xmm2,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
    Xmm8,
    Xmm9,
    Xmm10,
    Xmm11,
    Xmm12,
    Xmm13,
    Xmm14,
    Xmm15,
    St0, 
    St1, 
    St2, 
    St3,
    St4, 
    St5, 
    St6, 
    St7, 
    Mm0, 
    Mm1, 
    Mm2, 
    Mm3,
    Mm4, 
    Mm5, 
    Mm6, 
    Mm7, 
    Rflags,
    Es,
    Cs,
    Ss,
    Ds,
    Fs,
    Gs,
    __None,
    __None1,
    Fs_base,
    Gs_base,
    __None2,
    __None3,
    Tr,
    Ldtr,
    Mxcsr,
    Fcw,
    Fsw,

}

GDBUnwindRegGet :: distinct proc "c" (self: ^GDBUnwindCallbacks, reg: GDBReg);
GDBUnwindRegSet :: distinct proc "c" (self: ^GDBUnwindCallbacks, reg: GDBReg, val: ^GDBRegValue);
GDBUnwindCallbacks :: struct {
    reg_set: GDBUnwindRegSet,
    reg_get: GDBUnwindRegGet,
    target_read: GDBTargetRead,
    priv_data: [^]u8,
}

GDBReadDebugInfo :: distinct proc "c" (self: ^GDBReaderFuncs, cb: ^GDBSymbolCallbacks, memory: [^]u8, memory_sz: i32) -> GDBStatus
GDBUnwindFrame :: distinct proc "c" (self: ^GDBReaderFuncs, cb: ^GDBUnwindCallbacks) -> GDBStatus
GDBGetFrameId :: distinct proc "c" (self: ^GDBReaderFuncs, cb: ^GDBUnwindCallbacks) -> GDBFrameId
GDBDestroyReader :: distinct proc "c" (self: ^GDBReaderFuncs)
main :: proc() {
    ctx = context
}
