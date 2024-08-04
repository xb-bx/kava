//+build linux
package vm
import "x86asm:x86asm"
import "kava:classparser"
import "kava:shared"
import "core:fmt"
import "core:sys/unix"
import "base:runtime"
import "core:strings"
import "core:math"
import "core:mem/virtual"
import "core:os"
import "core:path/filepath"
import "core:slice"

parameter_registers := [?]x86asm.Reg64 { x86asm.rdi, x86asm.rsi, x86asm.rdx, x86asm.rcx, x86asm.r8, x86asm.r9 }
jit_prepare_locals :: proc(method: ^Method, locals: []i32, assembler: ^x86asm.Assembler) -> int {
    using x86asm
    reg_args_a := [?]Reg64{rdi, rsi, rdx, rcx, r8, r9}
    reg_args := reg_args_a[:]
    sub_size:int = 0
    if len(locals) != 0 {
        last:i32 = locals[len(locals) - 1]
        sub_size = -cast(int)last
    }
    stack_size := cast(int)method.code.(classparser.CodeAttribute).max_stack * 8
    sub_size += stack_size + 64
    if sub_size % 16 != 0 {
        sub_size += 8
    }
    subsx(assembler, rsp, i32(sub_size))
    static := false
    if !hasFlag(method.access_flags, classparser.MethodAccessFlags.Static) { 
        reg_args = reg_args_a[1:]
        mov(assembler, at(rbp, locals[0]), rdi)
    } else {
        reg_args = reg_args_a[0:]
        static = true
    }
    regular, fp := split_args_into_regular_and_fp(method.args) 
    defer delete(regular)
    defer delete(fp)
    regi := 0
    for regular_arg in regular {
        local := static ? locals[regular_arg.original_index] : locals[regular_arg.original_index + 1]
        if regi < len(reg_args) {
            mov(assembler, at(rbp, local), reg_args[regi]) 
            regi += 1
        } 
        else {
            index: i32 = i32(regular_arg.index - min(len(regular), len(reg_args)) - min(len(fp), 8))
            mov(assembler, rax, at(rbp, cast(i32)(16 + index * 8)))
            mov(assembler, at(rbp, local), rax)
        }
    }
    xmmi := 0
    for fp_arg in fp {
        local := static ? locals[fp_arg.original_index] : locals[fp_arg.original_index + 1]
        if xmmi <= 7 {
            movsd(assembler, at(rbp, local), Xmm(xmmi)) 
            xmmi += 1
        } else {
            index: i32 = i32(fp_arg.index - min(len(regular), len(reg_args)) - min(len(fp), 8))
            mov(assembler, rax, at(rbp, cast(i32)(16 + index * 8)))
            mov(assembler, at(rbp, local), rax)
        }
    }
    return sub_size
}

jit_invoke_method :: proc(using ctx: ^JittingContext, target: ^Method, instruction: classparser.Instruction, virtual_call: bool = true) {
    using x86asm
    virtual := virtual_call && !hasFlag(target.access_flags, classparser.MethodAccessFlags.Final) && (get_instr_opcode(instruction) == classparser.Opcode.invokevirtual || get_instr_opcode(instruction) == classparser.Opcode.invokeinterface) 
    args := count_args(target)
    regular, fp := split_args_into_regular_and_fp(target.args)
    defer delete(regular)
    defer delete(fp)
    if virtual {
        mov(assembler, rdi, transmute(int)vm)
        mov(assembler, rsi, at(rbp, stack_base - 8 * (stack_count - args)))
        mov(assembler, rdx, transmute(int)target)
        mov(assembler, rax, transmute(int)jit_resolve_virtual)
        call(assembler, rax)
        mov(assembler, r10, rax)
    }

    registers := [?]Reg64 {rsi, rdx, rcx, r8, r9}

    extra_args_size : i32 = 0
    if len(regular) > len(registers) {
        extra_args_size += i32(len(regular) - len(registers)) * 8
    }
    if len(fp) > 8 {
        extra_args_size += i32(len(fp) - 8) * 8
    }
    if extra_args_size > 0 {
        subsx(assembler, Reg64.Rsp, align_size(extra_args_size, 16))
    }
    regi := 0
    fisrt_arg_index: i32 = stack_count - args
    for regular_arg,i in regular {
        if i < len(registers) {
            mov(assembler, registers[i], at(rbp, stack_base - 8 * (fisrt_arg_index + 1 + i32(regular_arg.index))))
        }
        else {
            index: i32 = i32(regular_arg.index - min(len(regular), len(registers)) - min(len(fp), 8))
            mov(assembler, rax, at(rbp, stack_base - 8 * (fisrt_arg_index + 1 + i32(regular_arg.index))))
            mov(assembler, at(rsp, 8 * index), rax)
        }
    }
    for fp_arg, i in fp {
        if i < 8 {
            movsd(assembler, Xmm(i), at(rbp, stack_base - 8 * (fisrt_arg_index + 1 + i32(fp_arg.index))))
        }
        else {
            index: i32 = i32(fp_arg.index - min(len(regular), len(registers)) - min(len(fp), 8))
            mov(assembler, rax, at(rbp, stack_base - 8 * (fisrt_arg_index + 1 + i32(fp_arg.index))))
            mov(assembler, at(rsp, 8 * index), rax)
        }
    }
    stack_count -= args 
    mov(assembler, rdi, at(rbp, stack_base - 8 * stack_count))
    stack_count -= 1
    if virtual {
        call(assembler, at(r10))
    }
    else {
        mov(assembler, rax, transmute(int)&target.jitted_body)
        call(assembler, at(rax))
    }

    if extra_args_size != 0 {
        addsx(assembler, rsp, align_size(extra_args_size, 16))
    }

    if target.ret_type != vm.classes["void"] {
        stack_count += 1
        if target.ret_type.name == "float" || target.ret_type.name == "double" {
            movsd(assembler, at(rbp, stack_base - 8 * stack_count), xmm0)
        }
        else {
            mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
        }
    }

}
jit_invoke_static_impl :: proc(using ctx: ^JittingContext, target: ^Method) {
    using x86asm
    
    args := count_args(target)
    registers := [?]Reg64 {rdi, rsi, rdx, rcx, r8, r9}
//     if method.name == "<clinit>" {
//         initializer := find_method(target.parent, "<clinit>", "()V")
//         if initializer != nil {
//             already_initialized := create_label(assembler)
//             mov(assembler, rax, transmute(int)&target.parent.class_initializer_called)
//             mov(assembler, al, at(rax))
//             mov(assembler, r10b, u8(0))
//             cmp(assembler, al, r10b)
//             jne(assembler, already_initialized)
//             mov(assembler, rax, transmute(int)initializer)
//             call(assembler, rax)
//             set_label(assembler, already_initialized)
//         }
//         
// 
//     }
    regular, fp := split_args_into_regular_and_fp(target.args)
    defer delete(regular)
    defer delete(fp)
    extra_args_size : i32 = 0
    if len(regular) > len(registers) {
        extra_args_size += i32(len(regular) - len(registers)) * 8
    }
    if len(fp) > 8 {
        extra_args_size += i32(len(fp) - 8) * 8
    }
    if extra_args_size > 0 {
        subsx(assembler, Reg64.Rsp, align_size(extra_args_size, 16))
    }
    regi := 0
    fisrt_arg_index: i32 = stack_count - args
    for regular_arg,i in regular {
        if i < len(registers) {
            mov(assembler, registers[i], at(rbp, stack_base - 8 * (fisrt_arg_index + 1 + i32(regular_arg.index))))
        }
        else {
            index: i32 = i32(regular_arg.index - min(len(regular), len(registers)) - min(len(fp), 8))
            mov(assembler, rax, at(rbp, stack_base - 8 * (fisrt_arg_index + 1 + i32(regular_arg.index))))
            mov(assembler, at(rsp, 8 * index), rax)
        }
    }
    for fp_arg, i in fp {
        if i < 8 {
            movsd(assembler, Xmm(i), at(rbp, stack_base - 8 * (fisrt_arg_index + 1 + i32(fp_arg.index))))
        }
        else {
            index: i32 = i32(fp_arg.index - min(len(regular), len(registers)) - min(len(fp), 8))
            mov(assembler, rax, at(rbp, stack_base - 8 * (fisrt_arg_index + 1 + i32(fp_arg.index))))
            mov(assembler, at(rsp, 8 * index), rax)
        }
    }
    stack_count -= args 
    mov(assembler, rax, transmute(int)&target.jitted_body)
    call(assembler, at(rax))
    if extra_args_size != 0 {
        addsx(assembler, rsp, i32(extra_args_size))
    }

    if target.ret_type != vm.classes["void"] {
        stack_count += 1
        if target.ret_type.name == "float" || target.ret_type.name == "double" {
            movsd(assembler, at(rbp, stack_base - 8 * stack_count), xmm0)
        }
        else {
            mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
        }
    }
}


free_executable :: proc(ptr: [^]u8, size: uint) {
    assert(unix.sys_munmap(rawptr(ptr), size) == 0)
}

jit_ensure_clinit_called :: proc(using ctx: ^JittingContext, class: ^Class) {
    using x86asm
    this_class := ctx.method.parent 
    if is_subtype_of(this_class, class) {
        return
    }
    initializer := find_method(class, "<clinit>", "()V")
    if initializer != nil {
    
        mov(assembler, parameter_registers[0], transmute(int)vm)
        mov(assembler, parameter_registers[1], transmute(int)class)
        mov(assembler, parameter_registers[2], transmute(int)initializer)
        mov(assembler, rax, transmute(int)jit_ensure_clinit_called_body)
        call(assembler, rax)
    }
}
