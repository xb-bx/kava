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

    extra_args_size : i32 = (args - 4) * 8
    subsx(assembler, rsp, 32 + align_size(extra_args_size, 16))
    argi := 0
    first_arg_index := stack_count - args + 1
    for i in 0..<args {
        arg := target.args[argi]
        argi += 1
        if is_long_or_double(arg) {
            argi += 1
        }
        if i < 4 {
            if arg.name == "double" {
                movsd(assembler, Xmm(i), at(rbp, stack_base - 8 * (first_arg_index + i)))  
            } else if arg.name == "float" {
                movss(assembler, Xmm(i), at(rbp, stack_base - 8 * (first_arg_index + i)))  
            }
            else {
                mov(assembler, registers[i], at(rbp, stack_base - 8 * (first_arg_index + i)))  
            }
        } 
        else {
            mov(assembler, rax, at(rbp, stack_base - 8 * (first_arg_index + i)))
            mov(assembler, at(rsp, 32 + 8 * (i - 4)), rax)
        }
    }
    stack_count -= args
    mov(assembler, rax, transmute(int)&target.jitted_body)
    call(assembler, at(rax))
    addsx(assembler, rsp, 32 + align_size(extra_args_size, 16))
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


jit_invoke_method :: proc(using ctx: ^JittingContext, target: ^Method, instruction: classparser.Instruction, virtual_call: bool = true) {
    using x86asm
    virtual := !hasFlag(target.access_flags, classparser.MethodAccessFlags.Final) && (get_instr_opcode(instruction) == classparser.Opcode.invokevirtual || get_instr_opcode(instruction) == classparser.Opcode.invokeinterface) && virtual_call
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

    extra_args_size : i32 = (args - 3) * 8
    subsx(assembler, rsp, 32 + align_size(extra_args_size, 16))
    argi := 0
    first_arg_index := stack_count - args + 1
    for i in 0..<args {
        arg := target.args[argi]
        argi += 1
        if is_long_or_double(arg) {
            argi += 1
        }
        if i < 3 {
            if arg.name == "double" {
                movsd(assembler, Xmm(i), at(rbp, stack_base - 8 * (first_arg_index + i)))  
            } else if arg.name == "float" {
                movss(assembler, Xmm(i), at(rbp, stack_base - 8 * (first_arg_index + i)))  
            }
            else {
                mov(assembler, registers[i], at(rbp, stack_base - 8 * (first_arg_index + i)))  
            }
        } 
        else {
            mov(assembler, rax, at(rbp, stack_base - 8 * (first_arg_index + i)))
            mov(assembler, at(rsp, 32 + 8 * (i - 3)), rax)
        }
    }
    stack_count -= args
    mov(assembler, rcx, at(rbp, stack_base - stack_count * 8))
    stack_count -= 1
    if virtual {
        call(assembler, at(r10))
    }
    else {
        mov(assembler, rax, transmute(int)&target.jitted_body)
        call(assembler, at(rax))
    }
    addsx(assembler, rsp, 32 + align_size(extra_args_size, 16))
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

jit_prepare_locals :: proc(method: ^Method, locals: []i32, assembler: ^x86asm.Assembler) {
    using x86asm
    reg_args: []Reg64 = nil
    reg_args_a := [?]Reg64 { rcx, rdx, r8, r9 }

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
    static := false
    if !hasFlag(method.access_flags, classparser.MethodAccessFlags.Static) { 
        reg_args = reg_args_a[1:]
        mov(assembler, at(rbp, locals[0]), reg_args_a[0])
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
        if regular_arg.index < len(reg_args) {
            mov(assembler, at(rbp, local), reg_args[regular_arg.index]) 
        } 
        else {
            index: i32 = i32(regular_arg.index - len(reg_args))
            mov(assembler, rax, at(rbp, cast(i32)(16 + 32 + index * 8)))
            mov(assembler, at(rbp, local), rax)
        }
    }
    xmmi := 0
    for fp_arg in fp {
        local := static ? locals[fp_arg.original_index] : locals[fp_arg.original_index + 1]
        if fp_arg.index < len(reg_args)  {
            movsd(assembler, at(rbp, local), Xmm(fp_arg.index)) 
        } else {
            index: i32 = i32(fp_arg.index - len(reg_args))
            mov(assembler, rax, at(rbp, cast(i32)(16 + 32 + index * 8)))
            mov(assembler, at(rbp, local), rax)
        }
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
