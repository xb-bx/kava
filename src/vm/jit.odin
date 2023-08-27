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

ENABLE_GDB_DEBUGGING :: #config(ENABLE_GDB_DEBUGGING, true)

when ODIN_OS == .Windows {
    parameter_registers := [?]x86asm.Reg64 { x86asm.Reg64.Rcx, x86asm.Reg64.Rdx, x86asm.Reg64.R8, x86asm.Reg64.R9 }
} else {
    parameter_registers := [?]x86asm.Reg64 { x86asm.Reg64.Rdi, x86asm.Reg64.Rsi, x86asm.Reg64.Rdx, x86asm.Reg64.Rcx, x86asm.Reg64.R8, x86asm.Reg64.R9 }
}

JittingContext :: struct {
    vm: ^VM,
    method: ^Method,
    blocks: []CodeBlock,
    locals: []i32,
    assembler: ^x86asm.Assembler,
    labels: map[int]x86asm.Label,
    stack_base: i32,
    stack_count: i32,
    handle: os.Handle,
    line_mapping: [dynamic]shared.LineMapping,
    line: int,
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
    classparser.Opcode.aconst_null = 0,
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
write_replace_descriptor :: proc(builder: ^strings.Builder, str: string) {
    using strings
    for c in str {
        if c == '/' {
            write_rune(builder, '.')
        } else {
            write_rune(builder, c)
        }
    }
}
jit_create_bytecode_file_for_method :: proc(method: ^Method) -> (string, os.Handle) {
    if !os.exists("cache") {
        err := os.make_directory("cache", 0o777)
        if err != 0 {
            panic("could not create folder")
        }
    }

    using strings
    builder: Builder = {}
    builder_init(&builder)
    write_string(&builder, "cache/")
    write_replace_descriptor(&builder, method.parent.name)
    write_rune(&builder, '.')
    if method.name == "<init>" {
        write_string(&builder, "_init_")
    }
    else if method.name == "<clinit>" {
        write_string(&builder, "_clinit_")
    }
    else  {
        write_string(&builder, method.name)
    }
    write_replace_descriptor(&builder, method.descriptor)
    path := to_string(builder)
    handle, err := os.open(path, os.O_CREATE | os.O_WRONLY | os.O_TRUNC, 0o666)
    if err != 0 {
        fmt.println(err)
        fmt.println(path)
        panic("could not create file")
    }
    return path, handle
}
jit_method :: proc(vm: ^VM, method: ^Method, codeblocks: []CodeBlock) {
    using x86asm 
    assembler := Assembler {}
    when ODIN_DEBUG {
        init_asm(&assembler, true)
    } else {
        init_asm(&assembler, false)
    }
    locals := jit_method_prolog(method, &codeblocks[0], &assembler)
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
        line_mapping = make([dynamic]shared.LineMapping),
        line = 1,
    }
    stack_base:i32 = -size_of(StackEntry)
    if len(locals) > 0 {
        stack_base = locals[len(locals) - 1]
    }
    method.stack_base = stack_base
    jit_context.stack_base = stack_base
    if method.name == "<clinit>" {
        mov(&assembler, Reg64.Rax, 1)    
        mov(&assembler, Reg64.R10, transmute(u64)&method.parent.class_initializer_called)
        mov_to(&assembler, Reg64.R10, Reg64.R10)
    }
    when ENABLE_GDB_DEBUGGING {
        file, handle := jit_create_bytecode_file_for_method(method)
        jit_context.handle = handle
    }
    for &cb in codeblocks {
        jit_compile_cb(&jit_context, &cb)
    }
    when ENABLE_GDB_DEBUGGING {
        os.close(handle)
    }
    assemble(&assembler)
    when ODIN_DEBUG {
//         {
//         fmt.printf("%s.%s:%s\n", method.parent.name, method.name, method.descriptor)
//         fmt.println(locals)
//         fmt.println(stack_base)
//         for mnemonic in assembler.mnemonics {
//             fmt.println(mnemonic) 
//         }
//         for b in assembler.bytes {
//             fmt.printf("%2X", b)
//         }
//         fmt.println()
//         }
    }
    exceptions := method.code.(classparser.CodeAttribute).exception_table 
    method.exception_table = make([]ExceptionInfo, len(exceptions))
    for exception, i in exceptions {
        exc := ExceptionInfo {} 
        exc.start = cast(int)exception.start_pc
        exc.end = cast(int)exception.end_pc
        exc.exception = get_class(vm, method.parent.class_file, cast(int)exception.catch_type).value.(^Class)
        exc.offset = labels[cast(int)exception.handler_pc].offset
        method.exception_table[i] = exc
    }
    body := alloc_executable(len(assembler.bytes))
    for b, i in assembler.bytes {
        body[i] = b
    }
    for i in 0..<len(jit_context.line_mapping) {
        jit_context.line_mapping[i].pc += transmute(int)body
    }
    jit_context.line_mapping[0].pc = transmute(int)body
    method.jitted_body = body
    when ENABLE_GDB_DEBUGGING {
        symbol := new(shared.Symbol)
        defer free(symbol)
        ctx := context
        symbol.ctx = ctx
        symbol.file = strings.clone_to_cstring(file)
        defer delete(symbol.file)
        symbol.file_len = len(symbol.file)
        symbol.function = strings.clone_to_cstring(method.name)
        defer delete(symbol.function)
        symbol.function_len = len(symbol.function)
        symbol.line_mapping = slice.as_ptr(jit_context.line_mapping[:])
        symbol.line_mapping_len = len(jit_context.line_mapping)
        symbol.start = transmute(int)body
        symbol.end = symbol.start + len(assembler.bytes)
        entry := new(JitCodeEntry)
        defer free (entry)

        entry.next_entry = nil
        entry.prev_entry = nil
        entry.symfile = transmute([^]u8)symbol
        entry.size = size_of(shared.Symbol)
        __jit_debug_descriptor.relevant_entry = entry
        __jit_debug_descriptor.first_entry = entry
        __jit_debug_descriptor.action_flags = 1
        __jit_debug_register_code()

    }
    
}

jit_prepare_locals_indices :: proc(method: ^Method, cb_first: ^CodeBlock) -> []i32 {
    res := make([dynamic]i32)
    locali := 0
    offset: i32 = -8 - size_of(StackEntry)
    for locali < len(cb_first.locals) {
        append(&res, offset) 
        arg := cb_first.locals[locali]
        if arg != nil &&  (arg.primitive == PrimitiveType.Double || arg.primitive == PrimitiveType.Long) {
            append(&res, offset)
            locali += 1
        }
        locali += 1
        offset -= 8

    }
    return res[:]
}
jit_prepare_locals :: proc(method: ^Method, locals: []i32, assembler: ^x86asm.Assembler) {
    when ODIN_OS == .Windows {
        jit_prepare_locals_windows(method, locals, assembler)
    } else {
        jit_prepare_locals_systemv(method, locals, assembler)
    }
}
jit_prepare_locals_windows :: proc(method: ^Method, locals: []i32, assembler: ^x86asm.Assembler) {
    using x86asm
    reg_args: []Reg64 = nil
    reg_args_a := [?]Reg64 { Reg64.Rcx, Reg64.Rdx, Reg64.R8, Reg64.R9 }

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
    if !hasFlag(method.access_flags, classparser.MethodAccessFlags.Static) { 
        reg_args = reg_args_a[1:]
        mov_to(assembler, Reg64.Rbp, reg_args_a[0], locals[0])
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
            mov_to(assembler, Reg64.Rbp, reg_args[regi], locals[argi])
        } else {
            mov_to(assembler, Reg64.Rbp, reg_args[regi], locals[argi - 1])
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
        mov_from(assembler, Reg64.Rax, Reg64.Rbp, off)
        if !hasFlag(method.access_flags, classparser.MethodAccessFlags.Static) { 
            mov_to(assembler, Reg64.Rbp, Reg64.Rax, locals[rev_argi + 1])
        } else {
            mov_to(assembler, Reg64.Rbp, Reg64.Rax, locals[rev_argi])
        }
        rev_argi += 1
        off += 8
    }
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
    if !hasFlag(method.access_flags, classparser.MethodAccessFlags.Static) { 
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
        if !hasFlag(method.access_flags, classparser.MethodAccessFlags.Static) { 
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
        if !hasFlag(method.access_flags, classparser.MethodAccessFlags.Static) { 
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
    reg_args : []Reg64 = nil
    when ODIN_OS == .Windows {
        r := [?]Reg64 { Reg64.Rcx, Reg64.Rdx, Reg64.R8, Reg64.R9 }
        reg_args = r[:]
    } else {
        r := [?]Reg64 { Reg64.Rdi, Reg64.Rsi, Reg64.Rdx, Reg64.Rcx, Reg64.R8, Reg64.R9 }
        reg_args = r[:]
    }
    stack_count = cast(i32)cb.stack_at_start.count
    set_label(assembler, labels[cb.start])
    labels[cb.start] = { id = labels[cb.start].id, offset = len(assembler.bytes) }
    if cb.is_exception_handler {
        // push exception object onto the stack
        mov_to(assembler, Reg64.Rbp, Reg64.Rdi, stack_base - 8 * stack_count)
    }
    for instruction in cb.code {
        when ENABLE_GDB_DEBUGGING {
            append(&line_mapping, shared.LineMapping{ line = cast(i32)line, pc = len(assembler.bytes) })
            line += print_instruction_with_const(instruction, handle, method.parent.class_file, "")
        }
        assert(stack_count >= 0)
        #partial switch get_instr_opcode(instruction) {
            case .iconst_m1, .iconst_0, .iconst_1, .iconst_2, .iconst_3, .iconst_4, .iconst_5,
                .dconst_0, .dconst_1, .fconst_0, .fconst_1, .lconst_0, .lconst_1,
                .aconst_null:
                stack_count += 1
                const, ok := constants[get_instr_opcode(instruction)]
                assert(ok)
                mov(assembler, Reg64.Rax, const)
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .sipush:
                stack_count += 1
                mov(assembler, Reg64.Rax, transmute(u64)instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op)
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
                when ODIN_OS == .Windows { sub(assembler, Reg64.Rsp, 32 )}
                mov(assembler, Reg64.Rax, transmute(u64)stack_trace_pop)
                mov(assembler, Reg64.Rdi, transmute(u64)vm)
                call_reg(assembler, Reg64.Rax)
                when ODIN_OS == .Windows { add(assembler, Reg64.Rsp, 32 )}
                mov(assembler, Reg64.Rsp, Reg64.Rbp)
                pop(assembler, Reg64.Rbp)
                ret(assembler)
            case .ireturn, .areturn, .dreturn:
                when ODIN_OS == .Windows { sub(assembler, Reg64.Rsp, 32 )}
                mov(assembler, Reg64.Rax, transmute(u64)stack_trace_pop)
                mov(assembler, Reg64.Rdi, transmute(u64)vm)
                call_reg(assembler, Reg64.Rax)
                when ODIN_OS == .Windows { add(assembler, Reg64.Rsp, 32 )}
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
                        strobj :^ObjectHeader= nil
                        gc_alloc_string(vm, str, &strobj)
                        mov(assembler, Reg64.Rax, transmute(u64)strobj)
                    case:
                        fmt.println(const)
                        panic("should not happen")
                }
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .if_icmplt:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 2
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, Reg64.R10, Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                cmp(assembler, Reg32.R10d, Reg32.Eax)
                jlt(assembler, labels[start])
            case .if_icmple:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 2
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, Reg64.R10, Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                cmp(assembler, Reg32.R10d, Reg32.Eax)
                jle(assembler, labels[start])
            case .if_icmpge:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 2
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, Reg64.R10, Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                cmp(assembler, Reg32.R10d, Reg32.Eax)
                jge(assembler, labels[start])
            case .if_icmpgt:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 2
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, Reg64.R10, Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                cmp(assembler, Reg32.R10d, Reg32.Eax)
                jgt(assembler, labels[start])
            case .if_icmpeq, .if_acmpeq:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 2
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, Reg64.R10, Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                cmp(assembler, Reg64.Rax, Reg64.R10)
                je(assembler, labels[start])
            case .if_acmpne, .if_icmpne:
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
                mov(assembler, Reg64.Rax, transmute(u64)get_instr_offset(instruction))
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, pc)))
                jit_invoke_special(ctx, instruction)
            case .invokestatic:
                mov(assembler, Reg64.Rax, transmute(u64)get_instr_offset(instruction))
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, pc)))
                jit_invoke_static(ctx, instruction)
            case .invokevirtual:
                mov(assembler, Reg64.Rax, transmute(u64)get_instr_offset(instruction))
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, pc)))
                jit_invoke_virtual(ctx, instruction)
            case .irem:
                stack_count -= 2
                mov(assembler, Reg64.Rdx, 0)
                mov_from(assembler, Reg32.R10d, Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, Reg32.Eax, Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                idiv(assembler, Reg32.R10d)
                stack_count += 1
                mov_to(assembler, Reg64.Rbp, Reg64.Rdx, stack_base - 8 * stack_count)
            case .idiv:
                stack_count -= 2
                mov(assembler, Reg64.Rdx, 0)
                mov_from(assembler, Reg32.R10d, Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, Reg32.Eax, Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                idiv(assembler, Reg32.R10d)
                stack_count += 1
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .imul:
                mov(assembler, Reg64.Rdx, 0)
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
            
                fieldres := get_fieldrefconst_field(vm, method.parent.class_file, index)
                field := fieldres.value.(^Field)
                
                mov(assembler, Reg64.Rax, transmute(u64)&field.static_data)
                mov_from(assembler, Reg64.Rax, Reg64.Rax)
                stack_count += 1 
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .putfield:
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                field := get_fieldrefconst_field(vm, method.parent.class_file, index).value.(^Field)
                offset := field.offset
                assert(offset != 0)
                stack_count -= 2
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 2))
                mov_from(assembler, Reg64.R10, Reg64.Rbp, stack_base - 8 * (stack_count + 1))
                jit_null_check(assembler, Reg64.R10)  
                mov_to(assembler, Reg64.R10, Reg64.Rax, field.offset)
            case .getfield:
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                field := get_fieldrefconst_field(vm, method.parent.class_file, index).value.(^Field)
                offset := field.offset
                assert(offset != 0)
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * stack_count)
                jit_null_check(assembler, Reg64.Rax)  
                mov_from(assembler, Reg64.Rax, Reg64.Rax, offset)
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .ifne, .ifnonnull:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 1
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 1))
                mov(assembler, Reg64.R10, 0)
                cmp(assembler, Reg64.Rax, Reg64.R10)
                jne(assembler, labels[start])
            case .ifeq, .ifnull:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 1
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 1))
                mov(assembler, Reg64.R10, 0)
                cmp(assembler, Reg64.Rax, Reg64.R10)
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
            case .aaload:
                stack_count -= 2
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 1))
                jit_null_check(assembler, Reg64.Rax)
                mov_from(assembler, Reg64.R10, Reg64.Rbp, stack_base - 8 * (stack_count + 2))
                mov(assembler, Reg64.R11, 8)
                imul(assembler, Reg64.R10, Reg64.R11)
                add(assembler, Reg64.Rax, size_of(ArrayHeader))
                add(assembler, Reg64.Rax, Reg64.R10)
                mov(assembler, Reg32.R10d, 0)
                mov_from(assembler, Reg64.R10, Reg64.Rax)
                stack_count += 1
                mov_to(assembler, Reg64.Rbp, Reg64.R10, stack_base - 8 * stack_count)
            case .castore:
                stack_count -= 3
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 1))
                jit_null_check(assembler, Reg64.Rax)
                mov_from(assembler, Reg64.R10, Reg64.Rbp, stack_base - 8 * (stack_count + 2))
                mov_from(assembler, Reg64.R9, Reg64.Rbp, stack_base - 8 * (stack_count + 3))
                mov(assembler, Reg64.R11, 2)
                imul(assembler, Reg64.R10, Reg64.R11)
                add(assembler, Reg64.Rax, size_of(ArrayHeader))
                add(assembler, Reg64.Rax, Reg64.R10)
                mov_to(assembler, Reg64.Rax, Reg16.R9w, cast(i32)0)
            case .iastore:
                stack_count -= 3
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 1))
                jit_null_check(assembler, Reg64.Rax)
                mov_from(assembler, Reg64.R10, Reg64.Rbp, stack_base - 8 * (stack_count + 2))
                mov_from(assembler, Reg64.R9, Reg64.Rbp, stack_base - 8 * (stack_count + 3))
                mov(assembler, Reg64.R11, 4)
                imul(assembler, Reg64.R10, Reg64.R11)
                add(assembler, Reg64.Rax, size_of(ArrayHeader))
                add(assembler, Reg64.Rax, Reg64.R10)
                mov_to(assembler, Reg64.Rax, Reg32.R9d, cast(i32)0)
            case .iaload:
                stack_count -= 2
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + 1))
                jit_null_check(assembler, Reg64.Rax)
                mov_from(assembler, Reg64.R10, Reg64.Rbp, stack_base - 8 * (stack_count + 2))
                mov(assembler, Reg64.R11, 4)
                imul(assembler, Reg64.R10, Reg64.R11)
                add(assembler, Reg64.Rax, size_of(ArrayHeader))
                add(assembler, Reg64.Rax, Reg64.R10)
                mov(assembler, Reg32.R10d, 0)
                mov_from(assembler, Reg32.R10d, Reg64.Rax)
                stack_count += 1
                mov_to(assembler, Reg64.Rbp, Reg64.R10, stack_base - 8 * stack_count)
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
                mov_from(assembler, reg_args[0], Reg64.Rbp, stack_base - 8 * stack_count)
                mov(assembler, Reg64.Rax, transmute(u64)d2i)
                when ODIN_OS == .Windows { sub(assembler, Reg64.Rsp, 32) } 
                call_reg(assembler, Reg64.Rax)
                when ODIN_OS == .Windows { add(assembler, Reg64.Rsp, 32) } 
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .i2l:
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * stack_count)
                movsx_reg64_reg32(assembler, Reg64.Rax, Reg32.Eax)
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .i2c:
            case .i2d:
                mov_from(assembler, reg_args[0], Reg64.Rbp, stack_base - 8 * stack_count)
                mov(assembler, Reg64.Rax, transmute(u64)i2d)
                when ODIN_OS == .Windows { sub(assembler, Reg64.Rsp, 32) } 
                call_reg(assembler, Reg64.Rax)
                when ODIN_OS == .Windows { add(assembler, Reg64.Rsp, 32) } 
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .dmul:
                stack_count -= 2
                mov_from(assembler, reg_args[0], Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, reg_args[1], Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                mov(assembler, Reg64.Rax, transmute(u64)dmul)
                when ODIN_OS == .Windows { sub(assembler, Reg64.Rsp, 32) } 
                call_reg(assembler, Reg64.Rax)
                when ODIN_OS == .Windows { add(assembler, Reg64.Rsp, 32) } 
                stack_count += 1
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .dadd:
                stack_count -= 2
                mov_from(assembler, reg_args[0], Reg64.Rbp, stack_base - 8 * (stack_count + 2)) 
                mov_from(assembler, reg_args[1], Reg64.Rbp, stack_base - 8 * (stack_count + 1)) 
                mov(assembler, Reg64.Rax, transmute(u64)dadd)
                when ODIN_OS == .Windows { sub(assembler, Reg64.Rsp, 32) } 
                call_reg(assembler, Reg64.Rax)
                when ODIN_OS == .Windows { add(assembler, Reg64.Rsp, 32) } 
                stack_count += 1
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .iinc:
                ops := instruction.(classparser.SimpleInstruction).operand.(classparser.TwoOperands)
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, locals[ops.op1])
                imm :i32= cast(i32)ops.op2
                add(assembler, Reg64.Rax, imm)
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, locals[ops.op1])
            case .newarray:
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                mov(assembler, reg_args[0], transmute(u64)vm)
                typ := make_primitive(vm, array_type_primitives[index - 4], primitive_names[array_type_primitives[index - 4]], primitive_sizes[array_type_primitives[index - 4]])
                mov(assembler, reg_args[1], transmute(u64)typ)
                mov_from(assembler, reg_args[2], Reg64.Rbp, stack_base - 8 * stack_count)
                mov(assembler, reg_args[3], Reg64.Rbp)
                add(assembler, reg_args[3], stack_base - 8 * stack_count)
                mov(assembler, Reg64.Rax, transmute(u64)gc_alloc_array)
                when ODIN_OS == .Windows { sub(assembler, Reg64.Rsp, 32) } 
                call_reg(assembler, Reg64.Rax)
                when ODIN_OS == .Windows { add(assembler, Reg64.Rsp, 32) } 
            case .new:
                stack_count += 1 
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                mov(assembler, reg_args[0], transmute(u64)vm)
                mov(assembler, reg_args[1], transmute(u64)get_class(vm, method.parent.class_file, index).value.(^Class))
                mov(assembler, reg_args[2], Reg64.Rbp)
                add(assembler, reg_args[2], stack_base - 8 * stack_count)
                mov(assembler, reg_args[3], transmute(u64)cast(int)-1)
                mov(assembler, Reg64.Rax, transmute(u64)gc_alloc_object)
                when ODIN_OS == .Windows { sub(assembler, Reg64.Rsp, 32) } 
                call_reg(assembler, Reg64.Rax)
                when ODIN_OS == .Windows { add(assembler, Reg64.Rsp, 32) } 
            case .multianewarray:
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.TwoOperands).op1
                dimensions := cast(i32)instruction.(classparser.SimpleInstruction).operand.(classparser.TwoOperands).op2
                class := get_class(vm, method.parent.class_file, index).value.(^Class)
                stack_count -= dimensions
                elems_size := dimensions * 8
                if elems_size % 16 != 0 {
                    elems_size += 8
                }
                sub(assembler, Reg64.Rsp, cast(int)elems_size)
                mov(assembler, reg_args[2], Reg64.Rsp)
                for i in 1..=dimensions {
                    mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * (stack_count + i)) 
                    mov_to(assembler, reg_args[2], Reg64.Rax, (i - 1) * 8)
                }
                stack_count += 1
                mov(assembler, reg_args[0], transmute(u64)vm)
                mov(assembler, reg_args[1], transmute(u64)class)
                mov(assembler, reg_args[3], Reg64.Rbp)
                add(assembler, reg_args[3], stack_base - 8 * stack_count)
                mov(assembler, Reg64.Rax, transmute(u64)gc_alloc_multiarray)
                when ODIN_OS == .Windows { sub(assembler, Reg64.Rsp, 32) } 
                call_reg(assembler, Reg64.Rax)
                when ODIN_OS == .Windows { add(assembler, Reg64.Rsp, 32) } 
                add(assembler, Reg64.Rsp, elems_size)
            case .dup:
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * stack_count)
                stack_count += 1
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .athrow:
                sub(assembler, Reg64.Rsp, 16)
                mov(assembler, reg_args[0], transmute(u64)vm)
                mov_from(assembler, reg_args[1], Reg64.Rbp, stack_base - 8 * stack_count) 
                mov(assembler, reg_args[2], Reg64.Rsp)
                mov(assembler, Reg64.Rax, transmute(u64)throw)
                when ODIN_OS == .Windows { sub(assembler, Reg64.Rsp, 32) } 
                call_reg(assembler, Reg64.Rax)
                when ODIN_OS == .Windows { add(assembler, Reg64.Rsp, 32) } 
                mov_from(assembler, Reg64.Rdi, Reg64.Rbp, stack_base - 8 * stack_count)
                mov_from(assembler, Reg64.Rbp, Reg64.Rsp)
                jmp_reg_direct(assembler, Reg64.Rax)
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
            case .arraylength:
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * stack_count)
                jit_null_check(assembler, Reg64.Rax)
                mov_from(assembler, Reg64.Rax, Reg64.Rax, cast(i32)offset_of(ArrayHeader, length))
                mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
            case .tableswitch:
                table := instruction.(classparser.TableSwitch)
                mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * stack_count)
                stack_count -= 1
                mov(assembler, Reg64.R10, transmute(u64)table.low)
                cmp(assembler, Reg64.Rax, Reg64.R10)
                jlt(assembler, labels[table.default])
                mov(assembler, Reg64.R10, transmute(u64)table.high)
                cmp(assembler, Reg64.Rax, Reg64.R10)
                jgt(assembler, labels[table.default])
                sub(assembler, Reg64.Rax, table.low)
                mov(assembler, Reg64.R10, 0)
                for offset in table.offsets {
                    cmp(assembler, Reg64.Rax, Reg64.R10)
                    je(assembler, labels[offset])
                    add(assembler, Reg64.R10, 1)
                }
                jmp(assembler, labels[table.default])
            case:
                fmt.println(instruction)
                panic("unimplemented")
        }
    }
} 
throw :: proc "c" (vm: ^VM, exc: ^ObjectHeader, old_rbp: ^int) -> int {
    context = vm.ctx
    i := len(stacktrace) - 1
    items_to_remove := 0
    for i >= 0 {
        entry := stacktrace[i]
        table := entry.method.exception_table
        for exception in table {
            if exception.exception == exc.class ||  is_subtype_of(exc.class, exception.exception) {
                if entry.pc >= exception.start && entry.pc <= exception.end {
                    if items_to_remove > 0 {
                        start := len(stacktrace) - items_to_remove
                        remove_range(&stacktrace, start, start + items_to_remove)
                    }
                    old_rbp^ = entry.rbp
                    return transmute(int)entry.method.jitted_body + exception.offset 
                }
            }
        }
        items_to_remove += 1
        i -= 1
    }
    
    fmt.printf("Unhandled exception %s\n", exc.class.name)
    print_stack_trace()
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
jit_null_check :: proc(assembler: ^x86asm.Assembler, reg: x86asm.Reg64) {
    using x86asm
    assert(reg != Reg64.R11)
    oklabel := create_label(assembler)
    mov(assembler, Reg64.R11, 0)
    cmp(assembler, reg, Reg64.R11)
    jne(assembler, oklabel)
    sub(assembler, Reg64.Rsp, 16)
    mov(assembler, parameter_registers[0], transmute(u64)vm)
    mov(assembler, parameter_registers[1], transmute(u64)load_class(vm, "java/lang/NullPointerException").value.(^Class))
    mov(assembler, parameter_registers[2], Reg64.Rsp)
    mov(assembler, parameter_registers[3], transmute(u64)cast(int)-1)
    mov(assembler, Reg64.Rax, transmute(u64)gc_alloc_object)
    when ODIN_OS == .Windows { sub(assembler, Reg64.Rsp, 32) }
    call_reg(assembler, Reg64.Rax)
    when ODIN_OS == .Windows { add(assembler, Reg64.Rsp, 32) }
    mov(assembler, parameter_registers[0], transmute(u64)vm)
    mov_from(assembler, parameter_registers[1], Reg64.Rsp, 0)
    mov(assembler, parameter_registers[2], Reg64.Rsp)
    add(assembler, parameter_registers[2], 8)
    mov(assembler, Reg64.Rax, transmute(u64)throw)
    when ODIN_OS == .Windows { sub(assembler, Reg64.Rsp, 32) }
    call_reg(assembler, Reg64.Rax)
    when ODIN_OS == .Windows { add(assembler, Reg64.Rsp, 32) }
    mov_from(assembler, Reg64.Rdi, Reg64.Rsp, 0)
    mov_from(assembler, Reg64.Rbp, Reg64.Rsp, 8)
    jmp_reg_direct(assembler, Reg64.Rax)
    set_label(assembler, oklabel)
    
}
is_long_or_double :: proc(class: ^Class) -> bool {
    return class.name == "long" || class.name == "double"
}
jit_invoke_static :: proc(using ctx: ^JittingContext, instruction: classparser.Instruction) {
    when ODIN_OS == .Linux {
        jit_invoke_static_systemv(ctx, instruction)
    } else {
        jit_invoke_static_windows(ctx, instruction)
    }
}
jit_invoke_static_windows :: proc(using ctx: ^JittingContext, instruction: classparser.Instruction) {
    using x86asm
    
    index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
    target := get_methodrefconst_method(vm, method.parent.class_file, index).value.(^Method)     
    args := count_args(target)
    registers := [?]Reg64 { Reg64.Rcx, Reg64.Rdx, Reg64.R8, Reg64.R9 }
    if method.name == "<clinit>" {
        initializer := find_method(target.parent, "<clinit>", "()V")
        if initializer != nil {
            already_initialized := create_label(assembler)
            mov(assembler, Reg64.Rax, transmute(u64)&target.parent.class_initializer_called)
            mov_from(assembler, Reg8.Al, Reg64.Rax)
            mov(assembler, Reg8.R10b, 0)
            cmp(assembler, Reg8.Al, Reg8.R10b)
            jne(assembler, already_initialized)
            mov(assembler, Reg64.Rax, transmute(u64)initializer)
            sub(assembler, Reg64.Rsp, 32)
            call_reg(assembler, Reg64.Rax)
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
        sub(assembler, Reg64.Rsp, cast(int)extra_args_size)
        extra_args := args - len(registers)
        for argindex in len(registers)..<args {
            mov_from(assembler, Reg64.Rax, Reg64.Rbp, stack_base - 8 * stack_count)
            mov_to(assembler, Reg64.Rsp, Reg64.Rax, off)
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
        mov_from(assembler, registers[last_register_index - register_index], Reg64.Rbp, stack_base - 8 * stack_count)
        stack_count -= 1
        register_index += 1
    }

    mov(assembler, Reg64.Rax, transmute(u64)&target.jitted_body)
    sub(assembler, Reg64.Rsp, 32)
    call_at_reg(assembler, Reg64.Rax)
    if extra_args_size != 0 {
        add(assembler, Reg64.Rsp, extra_args_size + 32)
    } else {
        add(assembler, Reg64.Rsp, 32)
    }

    if target.ret_type != vm.classes["void"] {
        stack_count += 1
        mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
    }
}
jit_invoke_static_systemv :: proc(using ctx: ^JittingContext, instruction: classparser.Instruction) {
    using x86asm
    
    index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
    target := get_methodrefconst_method(vm, method.parent.class_file, index).value.(^Method)     
    args := count_args(target)
    registers := [?]Reg64 {Reg64.Rdi, Reg64.Rsi, Reg64.Rdx, Reg64.Rcx, Reg64.R8, Reg64.R9}
    if method.name == "<clinit>" {
        initializer := find_method(target.parent, "<clinit>", "()V")
        if initializer != nil {
            already_initialized := create_label(assembler)
            mov(assembler, Reg64.Rax, transmute(u64)&target.parent.class_initializer_called)
            mov_from(assembler, Reg8.Al, Reg64.Rax)
            mov(assembler, Reg8.R10b, 0)
            cmp(assembler, Reg8.Al, Reg8.R10b)
            jne(assembler, already_initialized)
            mov(assembler, Reg64.Rax, transmute(u64)initializer)
            call_reg(assembler, Reg64.Rax)
            set_label(assembler, already_initialized)
        }
        

    }

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
        mov_from(assembler, registers[last_register_index - register_index], Reg64.Rbp, stack_base - 8 * stack_count)
        stack_count -= 1
        register_index += 1
    }

    mov(assembler, Reg64.Rax, transmute(u64)&target.jitted_body)
    call_at_reg(assembler, Reg64.Rax)
    if extra_args_size != 0 {
        add(assembler, Reg64.Rsp, extra_args_size)
    }

    if target.ret_type != vm.classes["void"] {
        stack_count += 1
        mov_to(assembler, Reg64.Rbp, Reg64.Rax, stack_base - 8 * stack_count)
    }
}

jit_invoke_method_windows :: proc(using ctx: ^JittingContext, instruction: classparser.Instruction, virtual_call: bool = true) {
    using x86asm
    index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
    target := get_methodrefconst_method(vm, method.parent.class_file, index).value.(^Method)     
    virtual := !hasFlag(target.access_flags, classparser.MethodAccessFlags.Final) && get_instr_opcode(instruction) == classparser.Opcode.invokevirtual && virtual_call
    args := count_args(target)
    if virtual {
        mov(assembler, Reg64.Rcx, transmute(u64)vm)
        mov_from(assembler, Reg64.Rdx, Reg64.Rbp, stack_base - 8 * (stack_count - args))
        mov(assembler, Reg64.R8, transmute(u64)target)
        mov(assembler, Reg64.Rax, transmute(u64)jit_resolve_virtual)
        sub(assembler, Reg64.Rsp, 32)
        call_reg(assembler, Reg64.Rax)
        mov(assembler, Reg64.R10, Reg64.Rax)
    }

    registers := [?]Reg64 {Reg64.Rdx, Reg64.R8, Reg64.R9}

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
        mov_from(assembler, registers[last_register_index - register_index], Reg64.Rbp, stack_base - 8 * stack_count)
        stack_count -= 1
        register_index += 1
    }

    
    mov_from(assembler, Reg64.Rcx, Reg64.Rbp, stack_base - 8 * stack_count)
    stack_count -= 1
    if virtual {
        sub(assembler, Reg64.Rsp, 32)
        call_at_reg(assembler, Reg64.R10)
    }
    else {
        mov(assembler, Reg64.Rax, transmute(u64)&target.jitted_body)
        sub(assembler, Reg64.Rsp, 32)
        call_at_reg(assembler, Reg64.Rax)
    }

    if extra_args_size != 0 {
        add(assembler, Reg64.Rsp, extra_args_size + 32)
    }
    else {
        add(assembler, Reg64.Rsp, 32)
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
    virtual := !hasFlag(target.access_flags, classparser.MethodAccessFlags.Final) && get_instr_opcode(instruction) == classparser.Opcode.invokevirtual && virtual_call
    args := count_args(target)
    if virtual {
        mov(assembler, Reg64.Rdi, transmute(u64)vm)
        mov_from(assembler, Reg64.Rsi, Reg64.Rbp, stack_base - 8 * (stack_count - args))
        mov(assembler, Reg64.Rdx, transmute(u64)target)
        mov(assembler, Reg64.Rax, transmute(u64)jit_resolve_virtual)
        call_reg(assembler, Reg64.Rax)
        mov(assembler, Reg64.R10, Reg64.Rax)
    }

    registers := [?]Reg64 {Reg64.Rsi, Reg64.Rdx, Reg64.Rcx, Reg64.R8, Reg64.R9}

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
        mov_from(assembler, registers[last_register_index - register_index], Reg64.Rbp, stack_base - 8 * stack_count)
        stack_count -= 1
        register_index += 1
    }

    
    mov_from(assembler, Reg64.Rdi, Reg64.Rbp, stack_base - 8 * stack_count)
    stack_count -= 1
    if virtual {
        call_at_reg(assembler, Reg64.R10)
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
jit_invoke_special :: proc(ctx: ^JittingContext, instruction: classparser.Instruction) {
    when ODIN_OS == .Linux {
        jit_invoke_method_systemv(ctx, instruction, false)
    } else {
        jit_invoke_method_windows(ctx, instruction, false)
    }
}
jit_invoke_virtual :: proc(ctx: ^JittingContext, instruction: classparser.Instruction) {
    when ODIN_OS == .Linux {
        jit_invoke_method_systemv(ctx, instruction)
    } else {
        jit_invoke_method_windows(ctx, instruction, false)
    }
}
count_args :: proc(method: ^Method) -> i32 {
    argi : i32= 0
    args : i32 = 0
    for argi < cast(i32)len(method.args) {
        arg := method.args[argi]
        if is_long_or_double(arg) {
            argi += 1
        }
        argi += 1
        args += 1
    }
    return args
}
jit_resolve_virtual :: proc "c" (vm: ^VM, object: ^ObjectHeader, target: ^Method) -> ^[^]u8 {
    context = vm.ctx
    if object == nil {
        fmt.println("WARNING: null ref at virtual resolve")
        return nil
    }
    found :^Method= nil
    class := object.class
    for found == nil {
        found = find_method(class, target.name, target.descriptor)
        if found != nil && hasFlag(found.access_flags, classparser.MethodAccessFlags.Abstract) {
            found = nil
        }
        if found == nil {
            class = class.super_class
        }
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

jit_method_prolog :: proc(method: ^Method, cb: ^CodeBlock, assembler: ^x86asm.Assembler) -> []i32 {
    using x86asm
    push(assembler, Reg64.Rbp)
    mov(assembler, Reg64.Rbp, Reg64.Rsp)
    sub(assembler, Reg64.Rsp, size_of(StackEntry))
    indices := jit_prepare_locals_indices(method, cb)
    jit_prepare_locals(method, indices, assembler)

    mov(assembler, Reg64.Rax, transmute(u64)method)
    mov_to(assembler, Reg64.Rbp, Reg64.Rax, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, method)))
    mov(assembler, Reg64.Rax, 0)
    mov_to(assembler, Reg64.Rbp, Reg64.Rax, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, pc)))
    mov(assembler, Reg64.Rax, Reg64.Rbp)
    mov_to(assembler, Reg64.Rbp, Reg64.Rax, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, rbp)))
    mov(assembler, Reg64.Rax, transmute(u64)stack_trace_push)
    mov(assembler, ODIN_OS == .Windows ? Reg64.Rcx : Reg64.Rdi, Reg64.Rbp)
    sub(assembler, ODIN_OS == .Windows ? Reg64.Rcx : Reg64.Rdi, 32)
    when ODIN_OS == .Windows { sub(assembler, Reg64.Rsp, 32) }
    call_reg(assembler, Reg64.Rax)
    when ODIN_OS == .Windows { add(assembler, Reg64.Rsp, 32) }
    return indices
}
stacktrace := make([dynamic]^StackEntry)
stack_trace_push :: proc(stack_entry: ^StackEntry) {
    append(&stacktrace, stack_entry)
}
stack_trace_pop :: proc "c" (vm: ^VM) -> ^StackEntry {
    context = vm.ctx
    res := stacktrace[len(stacktrace) - 1] 
    ordered_remove(&stacktrace, len(stacktrace) - 1) 
    return res
}
print_stack_trace :: proc() {
    i := len(stacktrace) - 1
    for i >= 0 {
        method := stacktrace[i].method
        pc := stacktrace[i].pc
        fmt.printf("at %s.%s:%s @ %i\n", method.parent.name, method.name, method.descriptor, pc)
        i -= 1
    }
}
StackEntry :: struct {
    method: ^Method,
    pc: int,
    rbp: int,
    __: int,
}
