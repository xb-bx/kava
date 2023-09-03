//+build windows
package vm
import "x86asm:x86asm"
import "kava:classparser"
import "kava:shared"
import "core:fmt"
import "core:sys/unix"
import "core:runtime"
import "core:strings"
import "core:math"
import "core:mem/virtual"
import "core:os"
import "core:path/filepath"
import "core:slice"
parameter_registers := [?]x86asm.Reg64 { x86asm.rcx, x86asm.rdx, x86asm.r8, x86asm.r9 }
jit_invoke_static :: proc(using ctx: ^JittingContext, instruction: classparser.Instruction) {
    using x86asm
    
    index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
    target := get_methodrefconst_method(vm, method.parent.class_file, index).value.(^Method)     
    args := count_args(target)
    registers := [?]Reg64 { rcx, rdx, r8, r9 }
    if method.name == "<clinit>" {
        initializer := find_method(target.parent, "<clinit>", "()V")
        if initializer != nil {
            already_initialized := create_label(assembler)
            mov(assembler, rax, transmute(int)&target.parent.class_initializer_called)
            mov(assembler, al, at(rax))
            mov(assembler, r10b, u8(0))
            cmp(assembler, al, r10b)
            jne(assembler, already_initialized)
            mov(assembler, rax, transmute(int)initializer)
            subsx(assembler, rsp, i32(32))
            call(assembler, rax)
            set_label(assembler, already_initialized)
        }
        

    }

    extra_args_size : i32 = 0
    if args > len(registers) {
        extra_args_size = (args - len(registers)) * 8
        off := extra_args_size - 8
        if extra_args_size % 16 != 0 {
            extra_args_size += 8
        }
        subsx(assembler, rsp, extra_args_size)
        extra_args := args - len(registers)
        for argindex in len(registers)..<args {
            mov(assembler, rax, at(rbp, stack_base - 8 * stack_count))
            mov(assembler, at(rsp, off), rax)
            stack_count -= 1
            off -= 8
        }
    }

    argi := 0
    last_register_index := min(args, len(registers))-1 
    register_index: i32 = 0
    for argindex in 0..<min(args, len(registers)) {
        if argindex < 0 { break }
        arg := target.args[argi] 
        if is_long_or_double(arg) {
            argi += 1
        }
        argi += 1
        mov(assembler, registers[last_register_index - register_index], at(rbp, stack_base - 8 * stack_count))
        stack_count -= 1
        register_index += 1
    }

    mov(assembler, rax, transmute(int)&target.jitted_body)
    subsx(assembler, rsp, i32(32))
    call(assembler, at(rax))
    if extra_args_size != 0 {
        addsx(assembler, rsp, i32(extra_args_size + 32))
    } else {
        addsx(assembler, rsp, i32(32))
    }

    if target.ret_type != vm.classes["void"] {
        stack_count += 1
        mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
    }
}

jit_invoke_method :: proc(using ctx: ^JittingContext, instruction: classparser.Instruction, virtual_call: bool = true) {
    using x86asm
    index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
    target := get_methodrefconst_method(vm, method.parent.class_file, index).value.(^Method)     
    virtual := !hasFlag(target.access_flags, classparser.MethodAccessFlags.Final) && get_instr_opcode(instruction) == classparser.Opcode.invokevirtual && virtual_call
    args := count_args(target)
    if virtual {
        mov(assembler, rcx, transmute(int)vm)
        mov(assembler, rdx, at(rbp, stack_base - 8 * (stack_count - args)))
        mov(assembler, r8, transmute(int)target)
        mov(assembler, rax, transmute(int)jit_resolve_virtual)
        subsx(assembler, rsp, i32(32))
        call(assembler, rax)
        mov(assembler, r10, rax)
    }

    registers := [?]Reg64 {rdx, r8, r9}

    extra_args_size : i32 = 0
    if args > len(registers) {
        extra_args_size = (args - len(registers)) * 8
        off := extra_args_size - 8
        if extra_args_size % 16 != 0 {
            extra_args_size += 8
        }
        subsx(assembler, rsp, extra_args_size)
        extra_args := args - len(registers)
        for argindex in len(registers)..<args {
            mov(assembler, rax, at(rbp, stack_base - 8 * stack_count))
            mov(assembler, at(rsp, off), rax)
            stack_count -= 1
            off -= 8
        }
    }
    argi := 0
    last_register_index := min(args, len(registers))-1 
    register_index: i32 = 0
    for argindex in 0..<min(args, len(registers)) {
        if argindex < 0 { break }
        arg := target.args[argi] 
        if is_long_or_double(arg) {
            argi += 1
        }
        argi += 1
        mov(assembler, registers[last_register_index - register_index], at(rbp, stack_base - 8 * stack_count))
        stack_count -= 1
        register_index += 1
    }

    
    mov(assembler, rcx, at(rbp, stack_base - 8 * stack_count))
    stack_count -= 1
    if virtual {
        subsx(assembler, rsp, i32(32))
        call(assembler, at(r10))
    }
    else {
        mov(assembler, rax, transmute(int)&target.jitted_body)
        subsx(assembler, rsp,i32(32))
        call(assembler, at(rax))
    }

    if extra_args_size != 0 {
        addsx(assembler, rsp, extra_args_size + 32)
    }
    else {
        addsx(assembler, rsp, i32(32))
    }

    if target.ret_type != vm.classes["void"] {
        stack_count += 1
        mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
    }

}

jit_prepare_locals :: proc(method: ^Method, locals: []i32, assembler: ^x86asm.Assembler) {
    using x86asm
    reg_args: []Reg64 = nil
    reg_args_a := [?]Reg64 { rcx, rdx, r8, r9 }

    argi := 0
    regi := 0
    extra_args := false
    sub_size:int = 0
    if len(locals) != 0 {
        last:i32 = locals[len(locals) - 1]
        sub_size = -cast(int)last
    }
    stack_size := cast(int)method.code.(classparser.CodeAttribute).max_stack * 8
    sub_size += stack_size
    if sub_size % 16 != 0 {
        sub_size += 8
    }
    subsx(assembler, rsp, i32(sub_size))
    if !hasFlag(method.access_flags, classparser.MethodAccessFlags.Static) { 
        reg_args = reg_args_a[1:]
        mov(assembler, at(rbp, locals[0]), reg_args_a[0])
    } else {
        reg_args = reg_args_a[0:]
    }
    for argi < len(method.args) {
        if regi >= len(reg_args) {
            extra_args = true
            break
        }
        arg := method.args[argi]
        if arg.name == "double" || arg.name == "long" {
            argi += 1
        }
        argi += 1
        if !hasFlag(method.access_flags, classparser.MethodAccessFlags.Static) { 
            mov(assembler, at(rbp, locals[argi]), reg_args[regi])
        } else {
            mov(assembler, at(rbp, locals[argi - 1]), reg_args[regi])
        }
        regi += 1
    }
    rev_argi := argi
    off: i32 = 16 + 32
    for rev_argi < len(method.args) {
        arg := method.args[rev_argi]
        if arg.name == "double" || arg.name == "long" {
            rev_argi += 1
        }
        mov(assembler, rax, at(rbp, off))
        if !hasFlag(method.access_flags, classparser.MethodAccessFlags.Static) { 
            mov(assembler, at(rbp, locals[rev_argi + 1]), rax)
        } else {
            mov(assembler, at(rbp, locals[rev_argi]), rax)
        }
        rev_argi += 1
        off += 8
    }
}

alloc_executable :: proc(size: uint) -> [^]u8 {
    data, err := virtual.memory_block_alloc(size, size, {})

    if err != virtual.Allocator_Error.None {
        panic("Failed to allocate executable memory")
    }
    ok := virtual.protect(data.base, data.reserved, { virtual.Protect_Flag.Read, virtual.Protect_Flag.Write, virtual.Protect_Flag.Execute})
    if !ok {
        panic("Failed to allocate executable memory")
    }
    return data.base
}
