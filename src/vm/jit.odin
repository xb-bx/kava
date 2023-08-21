package vm
import "x86asm:x86asm"
import "kava:classparser"
import "core:fmt"

jit_method :: proc(vm: ^VM, method: ^Method, codeblocks: []CodeBlock) -> []u8 {
    using x86asm 
    assembler := Assembler {}
    init_asm(&assembler)
    locals := jit_method_prolog(method, &assembler)
    for &cb in codeblocks {
        jit_compile_cb(vm, method, &assembler, locals, &cb, codeblocks)
    }
    assemble(&assembler)
    return assembler.bytes[:]
}

jit_prepare_locals_indices :: proc(method: ^Method) -> []i32 {
    res := make([dynamic]i32)
    locali := 0
    offset: i32 = -8
    for locali < len(method.locals) {
        append(&res, offset) 
        arg := method.locals[locali]
        if arg.primitive == PrimitiveType.Double || arg.primitive == PrimitiveType.Long {
            append(&res, offset)
            locali += 1
        }
        locali += 1
        offset -= 8

    }
    return res[:]
}
jit_prepare_locals_systemv :: proc(method: ^Method, locals: []i32, assembler: ^x86asm.Assembler) {
    using x86asm
    reg_args := [?]Reg64{Reg64.Rdi, Reg64.Rsi, Reg64.Rdx, Reg64.Rcx, Reg64.R8, Reg64.R9}
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
    sub(assembler, Reg64.Rsp, sub_size)
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
        mov_to(assembler, Reg64.Rbp, reg_args[regi], locals[argi - 1])
        regi += 1
    }
    rev_argi := len(method.args) - 1
    off: i32 = 16
    fmt.println(rev_argi, argi)
    for rev_argi >= argi {
        arg := method.args[rev_argi]
        if arg.name == "double" || arg.name == "long" {
            rev_argi -= 1
        }
        mov_from(assembler, Reg64.Rax, Reg64.Rbp, off)
        mov_to(assembler, Reg64.Rbp, Reg64.Rax, locals[rev_argi])
        rev_argi -= 1
        off += 8
    }
}
jit_compile_cb :: proc(vm: ^VM, method: ^Method, assembler: ^x86asm.Assembler, locals: []i32, cb: ^CodeBlock, other: []CodeBlock) {
    using classparser
    using x86asm 
    stack_base := locals[len(locals) - 1]
    stack_count: i32 = 0
    for instruction in cb.code {
        assert(stack_count >= 0)
        #partial switch get_instr_opcode(instruction) {
            case .iconst_4:
                stack_count += 1
                mov(assembler, Reg64.Rax, 4)
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .istore, .dstore, .fstore, .astore, .lstore:
                stack_count -= 1
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 1))
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, locals[index])
            case .aload, .iload, .fload, .lload, .dload:
                stack_count += 1
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, locals[index])
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)

            case .ldc2_w:
                stack_count += 1
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                const := method.parent.class_file.constant_pool[index - 1]
                #partial switch in const {
                    case DoubleInfo:
                        mov(assembler, Reg64.Rax, transmute(u64)const.(classparser.DoubleInfo).value)  
                    case LongInfo:
                        mov(assembler, Reg64.Rax, transmute(u64)const.(classparser.LongInfo).value)  
                    case:
                        panic("should not happen")
                }
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case ._return:
                mov(assembler, Reg64.Rsp, Reg64.Rbp)
                pop(assembler, Reg64.Rbp)
                ret(assembler)
            case .invokespecial:
                jit_invoke_special(vm, method, assembler, locals, &stack_count, instruction)
            case:
                fmt.println(instruction)
                panic("unimplemented")
        }
    }
} 
jit_invoke_special :: proc(vm: ^VM, method: ^Method, assembler: ^x86asm.Assembler, locals: []i32, stack_count: ^i32, instruction: classparser.Instruction) {
    index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
    target := get_methodrefconst_method(vm, method.parent.class_file, index).value.(^Method)     
    if target.name == "<init>" && target.parent.name == "java/lang/Object" {
        
    } else {
        panic("")
    }
}

jit_method_prolog :: proc(method: ^Method, assembler: ^x86asm.Assembler) -> []i32 {
    using x86asm
    push(assembler, Reg64.Rbp)
    mov(assembler, Reg64.Rbp, Reg64.Rsp)
    indices := jit_prepare_locals_indices(method)
    jit_prepare_locals_systemv(method, indices, assembler)
    return indices
}
