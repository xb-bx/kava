package vm
import "x86asm:x86asm"
import "kava:classparser"
import "core:fmt"
import "core:sys/unix"
import "core:runtime"
import "core:strings"
import "core:math"

JittingContext :: struct {
    vm: ^VM,
    method: ^Method,
    blocks: []CodeBlock,
    locals: []i32,
    assembler: ^x86asm.Assembler,
    labels: map[int]x86asm.Label,
    stack_base: i32,
    stack_count: i32,
}


alloc_executable :: proc(size: uint) -> [^]u8 {
    when ODIN_OS == .Linux {
        base := transmute([^]u8)unix.sys_mmap(nil, size, unix.PROT_READ | unix.PROT_EXEC | unix.PROT_WRITE, unix.MAP_ANONYMOUS | unix.MAP_PRIVATE, -1, 0)
        return base
    }
    else {
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

}
constants := map[classparser.Opcode]u64 {
    classparser.Opcode.iconst_0 = 0,
    classparser.Opcode.iconst_1 = 1,
    classparser.Opcode.iconst_2 = 2,
    classparser.Opcode.iconst_3 = 3,
    classparser.Opcode.iconst_4 = 4,
    classparser.Opcode.iconst_5 = 5,
    classparser.Opcode.iconst_m1 = transmute(u64)cast(i64)-1,
    classparser.Opcode.dconst_0 = transmute(u64)cast(f64)0,
    classparser.Opcode.dconst_1 = transmute(u64)cast(f64)1,
    classparser.Opcode.fconst_0 = cast(u64)transmute(u32)cast(f32)0,
    classparser.Opcode.fconst_1 = cast(u64)transmute(u32)cast(f32)1,
    classparser.Opcode.lconst_0 = 0,
    classparser.Opcode.lconst_1 = 0,
    classparser.Opcode.aconst_null = 0,
}

jit_method :: proc(vm: ^VM, method: ^Method, codeblocks: []CodeBlock) {
    using x86asm 
    assembler := Assembler {}
    when ODIN_DEBUG {
        init_asm(&assembler, true)
    } else {
        init_asm(&assembler, false)
    }
    locals := jit_method_prolog(method, &assembler)
    labels := make(map[int]Label)
    for cb in codeblocks {
        labels[cb.start] = create_label(&assembler)
    }
    jit_context := JittingContext {
        vm = vm,
        method = method,
        blocks = codeblocks,
        locals = locals,
        assembler = &assembler,
        labels = labels,
    }
    stack_base:i32 = 0
    if len(locals) > 0 {
        stack_base = locals[len(locals) - 1]
    }
    jit_context.stack_base = stack_base
    if method.name == "hashCode" {
    }
    for &cb in codeblocks {
        jit_compile_cb(&jit_context, &cb)
    }
    assemble(&assembler)
    when ODIN_DEBUG {
        if method.parent.name == "HelloWorld" {
        fmt.printf("%s.%s:%s\n", method.parent.name, method.name, method.descriptor)
        fmt.println(locals)
        fmt.println(stack_base)
        for mnemonic in assembler.mnemonics {
            fmt.println(mnemonic) 
        }
        for b in assembler.bytes {
            fmt.printf("%2X", b)
        }
        fmt.println()
        }
    }
    body := alloc_executable(len(assembler.bytes))
    for b, i in assembler.bytes {
        body[i] = b
    }
    method.jitted_body = body
    
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
    reg_args: []Reg64 = nil
    reg_args_a := [?]Reg64{Reg64.Rdi, Reg64.Rsi, Reg64.Rdx, Reg64.Rcx, Reg64.R8, Reg64.R9}

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
    if !hasFlag(method.access_flags, classparser.MemberAccessFlags.Static) { 
        reg_args = reg_args_a[1:]
        mov_to(assembler, Reg64.Rbp, Reg64.Rdi, locals[0])
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
        if !hasFlag(method.access_flags, classparser.MemberAccessFlags.Static) { 
            mov_to(assembler, Reg64.Rbp, reg_args[regi], locals[argi])
        } else {
            mov_to(assembler, Reg64.Rbp, reg_args[regi], locals[argi - 1])
        }
        regi += 1
    }
    rev_argi := argi
    off: i32 = 16
    for rev_argi < len(method.args) {
        arg := method.args[rev_argi]
        if arg.name == "double" || arg.name == "long" {
            rev_argi += 1
        }
        mov_from(assembler, Reg64.Rax, Reg64.Rbp, off)
        if !hasFlag(method.access_flags, classparser.MemberAccessFlags.Static) { 
            mov_to(assembler, Reg64.Rbp, Reg64.Rax, locals[rev_argi + 1])
        } else {
            mov_to(assembler, Reg64.Rbp, Reg64.Rax, locals[rev_argi])
        }
        rev_argi += 1
        off += 8
    }
}
jit_compile_cb :: proc(using ctx: ^JittingContext, cb: ^CodeBlock) {
    using classparser
    using x86asm 
    set_label(assembler, labels[cb.start])
    for instruction in cb.code {
//         fmt.println(stack_count)
//         print_instruction(instruction)
        assert(stack_count >= 0)
        lbl := create_label(assembler)
        set_label(assembler, lbl)
        #partial switch get_instr_opcode(instruction) {
            case .iconst_m1, .iconst_0, .iconst_1, .iconst_2, .iconst_3, .iconst_4, .iconst_5,
                .dconst_0, .dconst_1, .fconst_0, .fconst_1, .lconst_0, .lconst_1:
                stack_count += 1
                const, ok := constants[get_instr_opcode(instruction)]
                assert(ok)
                mov(assembler, Reg64.Rax, const)
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .bipush:
                stack_count += 1
                mov(assembler, Reg64.Rax, transmute(u64)instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op)
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
            case .ireturn, .areturn, .dreturn:
                stack_count -= 1
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                mov(assembler, Reg64.Rsp, Reg64.Rbp)
                pop(assembler, Reg64.Rbp)
                ret(assembler)
            case .ldc:
                stack_count += 1
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                const := method.parent.class_file.constant_pool[index - 1]
                #partial switch in const {
                    case IntegerInfo:
                        mov(assembler, Reg64.Rax, transmute(u64)cast(i64)const.(classparser.IntegerInfo).value)  
                    case StringInfo:
                        str_index := const.(classparser.StringInfo).string_index
                        str := resolve_utf8(method.parent.class_file, str_index).(string)
                        strobj := gc_alloc_string(vm, str)
                        mov(assembler, Reg64.Rax, transmute(u64)strobj)
                    case:
                        fmt.println(const)
                        panic("should not happen")
                }
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .if_icmpge:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 2
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, Reg64.R10, Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                cmp(assembler, Reg32.R10d, Reg32.Eax)
                jge(assembler, labels[start])
            case .if_icmpeq, .if_acmpeq:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 2
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, Reg64.R10, Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                cmp(assembler, Reg64.Rax, Reg64.R10)
                je(assembler, labels[start])
            case .if_acmpne:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 2
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, Reg64.R10, Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                cmp(assembler, Reg64.Rax, Reg64.R10)
                jne(assembler, labels[start])
            case .goto, .goto_w:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                jmp(assembler, labels[start])
            case .invokespecial:
                jit_invoke_special(vm, method, assembler, locals, &stack_count, instruction)
            case .invokestatic:
                jit_invoke_static(ctx, instruction)
            case .invokevirtual:
                jit_invoke_virtual(ctx, instruction)
            case .imul:
                stack_count -= 2
                mov_from(assembler, Reg32.Eax, Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, Reg32.R10d, Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                imul(assembler, Reg64.Rax, Reg64.R10)
                stack_count += 1
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .iadd:
                stack_count -= 2
                mov_from(assembler, Reg32.Eax, Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, Reg32.R10d, Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                add(assembler, Reg32.Eax, Reg32.R10d)
                stack_count += 1
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .isub:
                stack_count -= 2
                mov_from(assembler, Reg32.Eax, Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, Reg32.R10d, Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                sub(assembler, Reg32.R10d, Reg32.Eax)
                stack_count += 1
                mov_to(assembler, Reg64.Rbp, Reg64.R10, stack_base - 8 * stack_count)
            case .ineg:
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * stack_count)
                neg(assembler, Reg64.Rax)
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)

            case .putstatic:
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                field := get_fieldrefconst_field(vm, method.parent.class_file, index).value.(^Field)
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * stack_count)
                mov(assembler, Reg64.R10, transmute(u64)&field.static_data)
                mov_to(assembler, Reg64.R10, Reg64.Rax)
            case .getstatic:
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                field := get_fieldrefconst_field(vm, method.parent.class_file, index).value.(^Field)
                mov(assembler, Reg64.Rax, transmute(u64)&field.static_data)
                mov_from(assembler, Reg64.Rax, Reg64.Rax)
                stack_count += 1 
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .getfield:
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                field := get_fieldrefconst_field(vm, method.parent.class_file, index).value.(^Field)
                offset := field.offset
                fmt.println("FIELD", field.name, index)
                assert(offset != 0)
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * stack_count)
                jit_null_check(assembler, Reg64.Rax)  
                mov_from(assembler, Reg64.Rax, Reg64.Rax, offset)
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .ifeq:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 1
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 1))
                mov(assembler, Reg64.R10, 0)
                je(assembler, labels[start])
            case .ifle:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 1
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 1))
                mov(assembler, Reg64.R10, 0)
                cmp(assembler, Reg64.Rax, Reg64.R10)
                jle(assembler, labels[start])
            case .ifgt:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 1
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 1))
                mov(assembler, Reg64.R10, 0)
                cmp(assembler, Reg64.Rax, Reg64.R10)
                jgt(assembler, labels[start])
            case .ifge:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 1
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 1))
                mov(assembler, Reg64.R10, 0)
                cmp(assembler, Reg64.Rax, Reg64.R10)
                jge(assembler, labels[start])
            case .caload:
                stack_count -= 2
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 1))
                jit_null_check(assembler, Reg64.Rax)
                mov_from(assembler, Reg64.R10, Reg64.Rbp, stack_base - 8 * (stack_count + 2))
                mov(assembler, Reg64.R11, 2)
                imul(assembler, Reg64.R10, Reg64.R11)
                add(assembler, Reg64.Rax, size_of(ArrayHeader))
                add(assembler, Reg64.Rax, Reg64.R10)
                mov(assembler, Reg32.R10d, 0)
                mov_from(assembler, Reg16.R10w, Reg64.Rax)
                stack_count += 1
                mov_to(assembler, Reg64.Rbp, Reg64.R10, stack_base - 8 * stack_count)
            case .d2i:
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * stack_count)
                mov(assembler, Reg64.Rsi, transmute(u64)d2i)
                call_reg(assembler, Reg64.Rax)
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .i2d:
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * stack_count)
                mov(assembler, Reg64.Rsi, transmute(u64)i2d)
                call_reg(assembler, Reg64.Rax)
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .dmul:
                stack_count -= 2
                mov_from(assembler, Reg64.Rdi, Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, Reg64.Rsi, Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                mov(assembler, Reg64.Rsi, transmute(u64)dmul)
                call_reg(assembler, Reg64.Rax)
                stack_count += 1
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .dadd:
                stack_count -= 2
                mov_from(assembler, Reg64.Rdi, Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, Reg64.Rsi, Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                mov(assembler, Reg64.Rsi, transmute(u64)dadd)
                call_reg(assembler, Reg64.Rax)
                stack_count += 1
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .iinc:
                ops := instruction.(classparser.SimpleInstruction).operand.(classparser.TwoOperands)
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, locals[ops.op1])
                imm :i32= cast(i32)ops.op2
                add(assembler, Reg64.Rax, imm)
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, locals[ops.op1])
            case .new:
                stack_count += 1 
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                mov(assembler, Reg64.Rdi, transmute(u64)vm)
                mov(assembler, Reg64.Rsi, transmute(u64)get_class(vm, method.parent.class_file, index).value.(^Class))
                mov(assembler, Reg64.Rdx, transmute(u64)cast(int)-1)
                mov(assembler, Reg64.Rax, transmute(u64)gc_alloc_object)
                call_reg(assembler, Reg64.Rax)
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .dup:
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * stack_count)
                stack_count += 1
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .athrow:
                mov(assembler, Reg64.Rdi, transmute(u64)vm)
                mov_from(assembler, Reg64.Rsi, Reg64.Rbp, stack_base - 8 * stack_count) 
                mov(assembler, Reg64.Rdx, transmute(u64)method)
                mov(assembler, Reg64.Rax, transmute(u64)throw)
                call_reg(assembler, Reg64.Rax)
            case .instanceof:
                fals := create_label(assembler)                
                end := create_label(assembler)
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * stack_count)
                jit_null_check(assembler, Reg64.Rax)
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                mov(assembler, Reg64.R10, transmute(u64)get_class(vm, method.parent.class_file, index).value.(^Class))
                mov_from(assembler, Reg64.Rax, Reg64.Rax)
                cmp(assembler, Reg64.Rax, Reg64.R10)
                jne(assembler, fals)
                mov(assembler, Reg64.Rax, 1)
                jmp(assembler, end)
                set_label(assembler, fals)
                mov(assembler, Reg64.Rax, 0)
                set_label(assembler, end)
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .checkcast:
                fals := create_label(assembler)                
                end := create_label(assembler)
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * stack_count)
                jit_null_check(assembler, Reg64.Rax)
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                mov(assembler, Reg64.R10, transmute(u64)get_class(vm, method.parent.class_file, index).value.(^Class))
                mov_from(assembler, Reg64.R11, Reg64.Rax)
                cmp(assembler, Reg64.R11, Reg64.R10)
                jne(assembler, fals)
                jmp(assembler, end)
                set_label(assembler, fals)
                mov(assembler, Reg64.Rax, 0)
                set_label(assembler, end)
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)

            case:
                fmt.println(instruction)
                panic("unimplemented")
        }
    }
} 
throw :: proc "c" (vm: ^VM, exc: ^ObjectHeader, method: ^Method) {
    context = vm.ctx
    fmt.printf("Exception %s at %s.%s:%s", exc.class.name, method.parent.name, method.name, method.descriptor)
    panic("")
}
d2i :: proc "c" (d: f64) -> i32 {
    return cast(i32)d
}
i2d :: proc "c" (i: i32) -> f64 {
    return cast(f64)i
}
dmul :: proc "c" (d1: f64, d2: f64) -> f64 {
    return d1 * d2
}
dadd :: proc "c" (d1: f64, d2: f64) -> f64 {
    return d1 + d2
}
jit_null_ref :: proc "c" () {
    context = {}
    panic("")
}
jit_null_check :: proc(assembler: ^x86asm.Assembler, reg: x86asm.Reg64) {
    using x86asm
    assert(reg != Reg64.R11)
    oklabel := create_label(assembler)
    mov(assembler, Reg64.R11, 0)
    cmp(assembler, reg, Reg64.R11)
    jne(assembler, oklabel)
    mov(assembler, Reg64.R11, transmute(u64)jit_null_ref)
    call_reg(assembler, Reg64.R11)
    set_label(assembler, oklabel)
    
}
is_long_or_double :: proc(class: ^Class) -> bool {
    return class.name == "long" || class.name == "double"
}
jit_invoke_static :: proc(using ctx: ^JittingContext, instruction: classparser.Instruction) {
    when ODIN_OS == .Linux {
        jit_invoke_static_systemv(ctx, instruction)
    } else {
        panic("")
    }
}
jit_pow :: proc "c" (i1: i32, i2: i32) -> i32 {
    return cast(i32)math.pow(cast(f64)i1, cast(f64)i2) 
}
jit_invoke_static_systemv :: proc(using ctx: ^JittingContext, instruction: classparser.Instruction) {
    using x86asm
    
    index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
    target := get_methodrefconst_method(vm, method.parent.class_file, index).value.(^Method)     
    args := count_args(target)
    argi := 0
    registers := [?]Reg64 {Reg64.Rdi, Reg64.Rsi, Reg64.Rdx, Reg64.Rcx, Reg64.R8, Reg64.R9}
    register_index :i32= 0

    extra_args_size : i32 = 0
    if args > 6 {
        extra_args_size = (args - 6) * 8
        off := extra_args_size - 8
        if extra_args_size % 16 != 0 {
            extra_args_size += 8
        }
        sub(assembler, Reg64.Rsp, cast(int)extra_args_size)
        extra_args := args - 6
        for argindex in 6..<args {
            mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * stack_count)
            mov_to(assembler, Reg64.Rsp, Reg64.Rax, off)
            stack_count -= 1
            off -= 8
        }
    }

    for argindex in 0..<min(args, 6) {
        arg := target.args[argi] 
        if is_long_or_double(arg) {
            argi += 1
        }
        argi += 1
        mov_from(assembler, registers[6 - 1 - register_index], Reg64.Rbp, stack_base - 8 * stack_count)
        stack_count -= 1
        register_index += 1
    }

    
    if target.name == "pow" {
        mov(assembler, Reg64.Rax, transmute(u64)jit_pow)
        call_reg(assembler, Reg64.Rax)
    }
    else {
        mov(assembler, Reg64.Rax, transmute(u64)&target.jitted_body)
        call_at_reg(assembler, Reg64.Rax)
    }

    if extra_args_size != 0 {
        add(assembler, Reg64.Rsp, extra_args_size)
    }

    if target.ret_type != vm.classes["void"] {
        stack_count += 1
        mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
    }
}

jit_invoke_method_systemv :: proc(using ctx: ^JittingContext, instruction: classparser.Instruction, virtual_call: bool = true) {
    using x86asm
    index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
    target := get_methodrefconst_method(vm, method.parent.class_file, index).value.(^Method)     
    virtual := !hasFlag(target.access_flags, classparser.MemberAccessFlags.Final) && get_instr_opcode(instruction) == classparser.Opcode.invokevirtual && virtual_call
    args := count_args(target)
    if virtual {
        mov(assembler, Reg64.Rdi, transmute(u64)vm)
        mov_from(assembler, Reg64.Rsi, Reg64.Rbp, stack_base - 8 * (stack_count - args))
        mov(assembler, Reg64.Rdx, transmute(u64)target)
        mov(assembler, Reg64.Rax, transmute(u64)jit_resolve_virtual)
        call_reg(assembler, Reg64.Rax)
        mov(assembler, Reg64.R10, Reg64.Rax)
    }

    argi := 0
    registers := [?]Reg64 {Reg64.Rsi, Reg64.Rdx, Reg64.Rcx, Reg64.R8, Reg64.R9}
    register_index :i32= 0

    extra_args_size : i32 = 0
    if args > len(registers) {
        extra_args_size = (args - len(registers)) * 8
        off := extra_args_size - 8
        if extra_args_size % 16 != 0 {
            extra_args_size += 8
        }
        sub(assembler, Reg64.Rsp, cast(int)extra_args_size)
        extra_args := args - len(registers)
        for argindex in len(registers)..<args {
            mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * stack_count)
            mov_to(assembler, Reg64.Rsp, Reg64.Rax, off)
            stack_count -= 1
            off -= 8
        }
    }

    for argindex in 0..<min(args, len(registers)) {
        arg := target.args[argi] 
        if is_long_or_double(arg) {
            argi += 1
        }
        argi += 1
        mov_from(assembler, registers[len(registers) - 1 - register_index], Reg64.Rbp, stack_base - 8 * stack_count)
        stack_count -= 1
        register_index += 1
    }

    
    mov_from(assembler, Reg64.Rdi, Reg64.Rbp, stack_base - 8 * stack_count)
    stack_count -= 1
    call_at_reg(assembler, Reg64.R10)

    if extra_args_size != 0 {
        add(assembler, Reg64.Rsp, extra_args_size)
    }

    if target.ret_type != vm.classes["void"] {
        stack_count += 1
        mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
    }

}
jit_invoke_special :: proc(vm: ^VM, method: ^Method, assembler: ^x86asm.Assembler, locals: []i32, stack_count: ^i32, instruction: classparser.Instruction) {
    index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
    target := get_methodrefconst_method(vm, method.parent.class_file, index).value.(^Method)     
    if target.name == "<init>" {
        stack_count^ = stack_count^ - 1        
    } else {
        panic("")
    }
}
java_lang_PrintStream_println :: proc "c" (stream: ^ObjectHeader, str: ^ObjectHeader) {
    context = {}
    chars := transmute(^ArrayHeader)get_object_field(str, "value") 
    offset := (get_object_field(str, "offset")) 
    chars_start := transmute(^u8)(transmute(int)chars + size_of(ArrayHeader))
    s := strings.string_from_ptr(chars_start, chars.length * 2)
    fmt.println(offset, get_object_field(str, "length"), s)
}
jit_invoke_virtual :: proc(ctx: ^JittingContext, instruction: classparser.Instruction) {
    when ODIN_OS == .Linux {
        jit_invoke_method_systemv(ctx, instruction)
    } else {
      panic("")  
    }
}
count_args :: proc(method: ^Method) -> i32 {
    argi :i32= 0
    for argi < cast(i32)len(method.args) {
        arg := method.args[argi]
        if is_long_or_double(arg) {
            argi += 1
        }
        argi += 1
    }
    return argi
}
jit_invoke_virtual_systemv :: proc(using ctx: ^JittingContext, instruction: classparser.Instruction) {
    using x86asm
    index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
    target := get_methodrefconst_method(vm, method.parent.class_file, index).value.(^Method)     
    pushed_to_stack := 0
    args :i32= 0
    mov(assembler, Reg64.Rdi, transmute(u64)vm)
    mov_from(assembler, Reg64.Rsi, Reg64.Rbp, stack_base - 8 * (stack_count - count_args(target)))
    mov(assembler, Reg64.Rdx, transmute(u64)target)
    mov(assembler, Reg64.Rax, transmute(u64)jit_resolve_virtual)
    call_reg(assembler, Reg64.Rax)
    mov(assembler, Reg64.R10, Reg64.Rax)
    reg_args := [?]Reg64{Reg64.Rsi, Reg64.Rdx, Reg64.Rcx, Reg64.R8, Reg64.R9}
    argi : i32 = 0 
    regi := 0
    extra_args := false
    real_count := 0
    extra_start := 0
    for argi < cast(i32)len(target.args) {
        if real_count == 6 {
            extra_start = cast(int)argi
        }
        real_count += 1
        if is_long_or_double(target.args[argi]) {
            argi += 1
        }
        argi += 1
    }
    if real_count > len(reg_args) {
        rev_argi: i32 = cast(i32)extra_start
        real_last: i32 = 6
        for rev_argi < cast(i32)len(target.args) {
            arg := target.args[rev_argi]
            pushed_to_stack += 1
            rev_argi += 1
            if is_long_or_double(arg) {
                rev_argi += 1
            }
            real_last += 1
        }
        real_last -= 1
        rev_argi = cast(i32)len(target.args) - 1 
        if pushed_to_stack % 2 == 1{
            push(assembler, 69)
        }
        rev_argi_real: i32 = 6 
        for rev_argi >= cast(i32)extra_start {
            arg := target.args[rev_argi]
            rev_argi -= 1
            args += 1
            if is_long_or_double(arg) {
                rev_argi -= 1
            }
            mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - real_last * 8) 
            push(assembler, Reg64.Rax)
            stack_count -= 1
        }
    }
    argi = 0
    for argi < cast(i32)len(target.args) {
        if regi >= len(reg_args) {
            extra_args = true
            break
        }
        args += 1
        arg := target.args[argi]
        argi += 1
        if is_long_or_double(arg) {
            argi += 1
        }
        assert(stack_count > 0)
        mov_from(assembler, reg_args[regi], Reg64.Rbp, stack_base - stack_count * 8)
        regi += 1
        stack_count -= 1
        
    }
    mov_from(assembler, Reg64.Rdi, Reg64.Rbp, stack_base - stack_count * 8)
    stack_count -= 1
    if target.name == "println" {
        mov(assembler, Reg64.Rax, transmute(u64)java_lang_PrintStream_println)
        call_reg(assembler, Reg64.Rax)
    }
    else {
        call_at_reg(assembler, Reg64.R10)
    }
    if pushed_to_stack % 2 == 1{
        pop(assembler, Reg64.R10)
    }
    if target.ret_type != vm.classes["void"] {
        stack_count += 1
        mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - stack_count * 8)
    } 

}
jit_resolve_virtual :: proc "c" (vm: ^VM, object: ^ObjectHeader, target: ^Method) -> ^[^]u8 {
    context = vm.ctx
    if object == nil {
        fmt.println("WARNING: null ref at virtual resolve")
        return nil
    }
    found :^Method= nil
    for found == nil {
        found = find_method(object.class, target.name, target.descriptor)
    }
    if found == nil {
        panic("")
    }
    return &found.jitted_body
}
find_method :: proc(class: ^Class, name: string, descriptor: string) -> ^Method {
    for &method in class.methods {
        if method.name == name && method.descriptor == descriptor {
            return &method
        }
    }
    return nil
}

jit_method_prolog :: proc(method: ^Method, assembler: ^x86asm.Assembler) -> []i32 {
    using x86asm
    push(assembler, Reg64.Rbp)
    mov(assembler, Reg64.Rbp, Reg64.Rsp)
    indices := jit_prepare_locals_indices(method)
    jit_prepare_locals_systemv(method, indices, assembler)
    return indices
}
