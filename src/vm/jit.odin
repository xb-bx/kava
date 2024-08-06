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

ENABLE_GDB_DEBUGGING :: #config(ENABLE_GDB_DEBUGGING, true)
BREAKPOINT_METHOD_NAME :: #config(BREAKPOINT_METHOD_NAME, "")
BREAKPOINT_CLASS_NAME :: #config(BREAKPOINT_CLASS_NAME, "")
BREAKPOINT_METHOD_DESCRIPTOR :: #config(BREAKPOINT_METHOD_DESCRIPTOR, "")

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


constants := map[classparser.Opcode]int {
    classparser.Opcode.aconst_null = 0,
    classparser.Opcode.iconst_0 = 0,
    classparser.Opcode.iconst_1 = 1,
    classparser.Opcode.iconst_2 = 2,
    classparser.Opcode.iconst_3 = 3,
    classparser.Opcode.iconst_4 = 4,
    classparser.Opcode.iconst_5 = 5,
    classparser.Opcode.iconst_m1 = transmute(int)cast(i64)-1,
    classparser.Opcode.dconst_0 = transmute(int)cast(f64)0,
    classparser.Opcode.dconst_1 = transmute(int)cast(f64)1,
    classparser.Opcode.fconst_0 = transmute(int)cast(u64)transmute(u32)cast(f32)0,
    classparser.Opcode.fconst_1 = transmute(int)cast(u64)transmute(u32)cast(f32)1,
    classparser.Opcode.lconst_0 = 0,
    classparser.Opcode.lconst_1 = 1,
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
LAZY_LENGTH :: 512 
jit_method_lazy :: proc "c" (vm: ^VM, method: ^Method, body_size: ^int = nil) -> [^]u8 {
    context = vm.ctx
    if hasFlag(method.access_flags, classparser.MethodAccessFlags.Native) {
        body, ok := vm.natives_table[method]
        if !ok {
            fmt.println(method.name, method.descriptor, method.parent.name)
            print_stack_trace()
            panic("Unknown native")
        }
        return body
    }
    res := split_method_into_codeblocks(vm, method)

    if res.is_err {
        print_verification_error(res.error.(VerificationError))
        panic("jit failed")
    }
    
    if method.jitted_body != nil {
        executable_free(&vm.exe_allocator, method.jitted_body)
    }
    size := jit_method(vm, method, res.value.([]CodeBlock))
    if body_size != nil {
        body_size^ = size
    }
    return method.jitted_body
}
@export
@(link_name="jit_vm")
vm : ^VM = nil
jit_method :: proc(_vm: ^VM, method: ^Method, codeblocks: []CodeBlock) -> int {
    using x86asm 
    assert(_vm != nil)
    vm = _vm
    assembler := Assembler {}
    when ODIN_DEBUG {
        init_asm(&assembler, true)
    } else {
        init_asm(&assembler, false)
    }
    if method.name == BREAKPOINT_METHOD_NAME && method.parent.name == BREAKPOINT_CLASS_NAME && method.descriptor == BREAKPOINT_METHOD_DESCRIPTOR {
        int3(&assembler)
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
        mov(&assembler, r10, transmute(int)&method.parent.class_initializer_called)
        movsx(&assembler, at(r10), i32(1))
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
        if exception.catch_type == 0 {
            exc.exception = load_class(vm, "java/lang/Throwable").value.(^Class)
        }
        else {
            exc.exception = get_class(vm, method.parent.class_file, cast(int)exception.catch_type).value.(^Class)
        }
        exc.offset = labels[cast(int)exception.handler_pc].offset
        method.exception_table[i] = exc
    }
    body := exealloc_alloc(&vm.exe_allocator, len(assembler.bytes))
    assert(body != nil)
    for b, i in assembler.bytes {
        body[i] = b
    }
    method.jitted_body = body
    when ENABLE_GDB_DEBUGGING {
        for i in 0..<len(jit_context.line_mapping) {
            jit_context.line_mapping[i].pc += transmute(int)body
        }
        jit_context.line_mapping[0].pc = transmute(int)body
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
    return len(assembler.bytes)
    
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
ArgInfo :: struct {
    type: ^Class,
    index: int,
    original_index: int,
}
split_args_into_regular_and_fp :: proc(args: []^Class) -> ([]ArgInfo, []ArgInfo) {
    argi := 0
    regular := make([]ArgInfo, len(args))
    regulari := 0
    fp := make([]ArgInfo, len(args))
    fpi := 0
    index := 0
    for argi < len(args) {
        arg := args[argi]
        if arg.name == "float" || arg.name == "double" {
            fp[fpi] = ArgInfo {
                type = arg,
                index = index,
                original_index = argi,
            }
            fpi += 1
        }
        else {
            regular[regulari] = ArgInfo {
                type = arg,
                index = index,
                original_index = argi,
            }
            regulari += 1
        }
        if is_long_or_double(arg) {
            argi += 1
        } 
        argi += 1
        index += 1
    }

    return regular[:regulari], fp[:fpi]
}
jit_array_load :: proc(using ctx: ^JittingContext, instruction: classparser.Instruction, elem_size: int) {
    using x86asm
    stack_count -= 2
    mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 1)))
    jit_null_check(ctx, rax, get_instr_offset(instruction))
    mov(assembler, r10d, at(rbp, stack_base - 8 * (stack_count + 2)))
    jit_bounds_check(ctx, rax, r10d, get_instr_offset(instruction))
    xor(assembler, r11, r11)
    switch elem_size {
        case 1:
            mov(assembler, r11b, at(rax, r10, i32(size_of(ArrayHeader)), 1))
        case 2:
            mov(assembler, r11w, at(rax, r10, i32(size_of(ArrayHeader)), 2))
        case 4:
            mov(assembler, r11d, at(rax, r10, i32(size_of(ArrayHeader)), 4))
        case 8:
            mov(assembler, r11, at(rax, r10, i32(size_of(ArrayHeader)), 8))
    }
    stack_count += 1
    mov(assembler, at(rbp, stack_base - 8 * stack_count), r11)
}
jit_array_store :: proc(using ctx: ^JittingContext, instruction: classparser.Instruction, elem_size: int) {
    using x86asm
    stack_count -= 3
    mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 1)))
    jit_null_check(ctx, rax, get_instr_offset(instruction))
    mov(assembler, r10d, at(rbp, stack_base - 8 * (stack_count + 2)))
    jit_bounds_check(ctx, rax, r10d, get_instr_offset(instruction))
    mov(assembler, r9, at(rbp, stack_base - 8 * (stack_count + 3)))
    switch elem_size {
        case 1:
            mov(assembler, at(rax, r10, size_of(ArrayHeader), 1), r9b)
        case 2:
            mov(assembler, at(rax, r10, size_of(ArrayHeader), 2), r9w)
        case 4:
            mov(assembler, at(rax, r10, size_of(ArrayHeader), 4), r9d)
        case 8:
            mov(assembler, at(rax, r10, size_of(ArrayHeader), 8), r9)
    }
}
jit_compile_cb :: proc(using ctx: ^JittingContext, cb: ^CodeBlock) {
    using classparser
    using x86asm 
    reg_args : []Reg64 = nil
    when ODIN_OS == .Windows {
        r := [?]Reg64 { rcx, rdx, r8, r9 }
        reg_args = r[:]
    } else {
        r := [?]Reg64 { rdi, rsi, rdx, rcx, r8, r9 }
        reg_args = r[:]
    }
    stack_count = cast(i32)cb.stack_at_start.count
    set_label(assembler, labels[cb.start])
    labels[cb.start] = { id = labels[cb.start].id, offset = len(assembler.bytes) }
    if cb.is_exception_handler {
        // push exception object onto the stack
        mov(assembler, at(rbp, stack_base - 8 * stack_count), rdi)
    }
    for instruction, i in cb.code {
        when ENABLE_GDB_DEBUGGING {
            append(&line_mapping, shared.LineMapping{ line = cast(i32)line, pc = len(assembler.bytes) })
            line += print_instruction_with_const(instruction, handle, method.parent.class_file, "")
        }
        assert(stack_count >= 0 && stack_count <= i32(ctx.method.code.(classparser.CodeAttribute).max_stack))
        #partial switch get_instr_opcode(instruction) {
            case .nop:
            case .monitorenter:
                stack_count -= 1
            case .monitorexit:
                stack_count -= 1
            case .pop:
                stack_count -= 1
            case .pop2:
                stack_count -= 2
            case .iconst_m1, .iconst_0, .iconst_1, .iconst_2, .iconst_3, .iconst_4, .iconst_5,
                .dconst_0, .dconst_1, .fconst_0, .fconst_1, .lconst_0, .lconst_1,
                .aconst_null:
                stack_count += 1
                const, ok := constants[get_instr_opcode(instruction)]
                assert(ok)
                mov(assembler, rax, const)
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .sipush:
                stack_count += 1
                mov(assembler, rax, transmute(int)instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op)
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .bipush:
                stack_count += 1
                mov(assembler, rax, transmute(int)instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op)
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .istore, .dstore, .fstore, .astore, .lstore:
                stack_count -= 1
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                mov(assembler, rax, at(rbp,  stack_base - 8 * (stack_count + 1)))
                mov(assembler, at(rbp, locals[index]), rax)
            case .iload, .fload:
                stack_count += 1
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                mov(assembler, eax, at(rbp,  locals[index]))
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .aload, .lload, .dload:
                stack_count += 1
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                mov(assembler, rax, at(rbp,  locals[index]))
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)

            case .ldc2_w:
                stack_count += 1
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                const := method.parent.class_file.constant_pool[index - 1]
                #partial switch _ in const {
                    case DoubleInfo:
                        mov(assembler, rax, transmute(int)const.(classparser.DoubleInfo).value)  
                    case LongInfo:
                        mov(assembler, rax, transmute(int)const.(classparser.LongInfo).value)  
                    case:
                        panic("should not happen")
                }
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case ._return:
                when ODIN_OS == .Windows { subsx(assembler, rsp, i32(32)) }
                mov(assembler, rax, transmute(int)stack_trace_pop)
                mov(assembler, parameter_registers[0], transmute(int)vm)
                call(assembler, rax)
                when ODIN_OS == .Windows { addsx(assembler, rsp, i32(32)) }
                mov(assembler, rsp, rbp)
                pop(assembler, rbp)
                ret(assembler)
            case .dreturn, .freturn:
                when ODIN_OS == .Windows { subsx(assembler, rsp, i32(32)) }
                mov(assembler, rax, transmute(int)stack_trace_pop)
                mov(assembler, parameter_registers[0], transmute(int)vm)
                call(assembler, rax)
                when ODIN_OS == .Windows { addsx(assembler, rsp, i32(32)) }
                stack_count -= 1
                movsd(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 1))) 
                mov(assembler, rsp, rbp)
                pop(assembler, rbp)
                ret(assembler)
            case .ireturn, .areturn, .lreturn:
                subsx(assembler, rsp, i32(16))
                mov(assembler, rax, transmute(int)(uint(0xfffffffffffffff0)))
                and(assembler, rsp, rax)

                
                when ODIN_OS == .Windows { subsx(assembler, rsp, i32(32)) }
                mov(assembler, rax, transmute(int)stack_trace_pop)
                mov(assembler, parameter_registers[0], transmute(int)vm)
                call(assembler, rax)
                when ODIN_OS == .Windows { addsx(assembler, rsp, i32(32)) }
                //addsx(assembler, rsp, i32(8))
                stack_count -= 1
                mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                mov(assembler, rsp, rbp)
                pop(assembler, rbp)
                ret(assembler)
            case .ldc:
                stack_count += 1
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                const := method.parent.class_file.constant_pool[index - 1]
                #partial switch _ in const {
                    case IntegerInfo:
                        mov(assembler, rax, transmute(int)cast(i64)const.(classparser.IntegerInfo).value)  
                    case StringInfo:
                        jit_load_string_const :: proc "c" (class: ^Class, const: u16) -> ^ObjectHeader {
                            using classparser
                            context = vm.ctx
                            str := resolve_utf8(class.class_file, const).(string)
                            strobj :^ObjectHeader= nil
                            gc_alloc_string(vm, str, &strobj)
                            class.strings[const] = strobj
                            return strobj
                        }
                        patch :: proc "c" (start: uintptr, len: int, str_index: u16, class: ^Class) -> ^ObjectHeader {
                            obj := jit_load_string_const(class, str_index)
                            bytes := transmute([^]u8)start 
                            bytes[0] = 0x48; bytes[1] = 0xb8; // mov rax, ...
                            (transmute(^^ObjectHeader)&bytes[2])^ = obj
                            i := 10
                            for i < len {
                                bytes[i] = 0x90 // nop
                                i+=1
                            }
                            return obj
                            
                        }
                        // alloc new string and then patch code to be:
                        // mov rax, <new_string_addr>
                        // nop
                        // ..
                        // nop
                        start_index := len(assembler.bytes)
                        lea_rax_rip := [?]u8 { 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00 }
                        str_index := const.(classparser.StringInfo).string_index
                        append(&assembler.bytes, ..lea_rax_rip[:])
                        subsx(assembler, rax, i32(len(lea_rax_rip)))
                        mov(assembler, reg_args[0], rax)
                        mov(assembler, cast(Reg32)reg_args[2], cast(i32)str_index)
                        mov(assembler, reg_args[3], transmute(int)method.parent)
                        mov(assembler, rax, transmute(int)patch)
                        end_index := len(assembler.bytes) + 2 + 6 // "call rax" is 2 bytes long & "mov R32, len" is 6 bytes long
                        mov(assembler, cast(Reg32)reg_args[1], cast(i32)(end_index - start_index)) 
                        call(assembler, rax)


                    case ClassInfo:
                        class := load_class(vm, method.parent.class_file.constant_pool[const.(classparser.ClassInfo).name_index - 1].(classparser.UTF8Info).str).value.(^Class)
                        obj := get_class_object(vm, class)
                        mov(assembler, rax, transmute(int)obj)
                    case FloatInfo:
                        mov(assembler, eax, transmute(i32)const.(classparser.FloatInfo).value)
                    case:
                        fmt.println(const)
                        panic("should not happen")
                }
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .if_icmplt:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 2
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                cmp(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 2)))
                jlt(assembler, labels[start])
            case .if_icmple:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 2
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                cmp(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 2)))
                jle(assembler, labels[start])
            case .if_icmpge:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 2
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                cmp(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 2)))
                jge(assembler, labels[start])
            case .if_icmpgt:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 2
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                cmp(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 2)))
                jgt(assembler, labels[start])
            case .if_icmpeq:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 2
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                cmp(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 2)))
                je(assembler, labels[start])
            case .if_icmpne:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 2
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                cmp(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 2)))
                jne(assembler, labels[start])
            case .if_acmpne:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 2
                mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                cmp(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 2)))
                jne(assembler, labels[start])
            case .if_acmpeq:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 2
                mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                cmp(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 2)))
                je(assembler, labels[start])
            case .goto, .goto_w:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                jmp(assembler, labels[start])
//             case .invokedynamic:
//                 jit_invoke_dynamic(ctx, instruction)
            case .invokespecial:
                movsx(assembler, at(rbp, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, pc))), i32(get_instr_offset(instruction)))
                instr := instruction.(classparser.SimpleInstruction)
                jit_invoke_special(ctx, instruction)
            case .invokestatic:
                movsx(assembler, at(rbp, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, pc))), i32(get_instr_offset(instruction)))
                jit_invoke_static(ctx, instruction)
            case .invokeinterface:
                movsx(assembler, at(rbp, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, pc))), i32(get_instr_offset(instruction)))
                jit_invoke_interface(ctx, instruction)
            case .invokevirtual:
                movsx(assembler, at(rbp, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, pc))), i32(get_instr_offset(instruction)))
                jit_invoke_virtual(ctx, instruction)
            case .lrem:
                stack_count -= 2
                mov(assembler, rdx, 0)
                mov(assembler, r10, at(rbp, stack_base - 8 * (stack_count + 2))) 
                jit_div_by_zero_check(ctx, r10, get_instr_offset(instruction))
                mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                idiv(assembler, r10)
                stack_count += 1
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rdx)
            case .irem:
                stack_count -= 2
                mov(assembler, edx, 0)
                mov(assembler, r10d, at(rbp, stack_base - 8 * (stack_count + 2))) 
                jit_div_by_zero_check(ctx, r10, get_instr_offset(instruction))
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                cdq(assembler)
                idiv(assembler, r10)
                stack_count += 1
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rdx)
            case .idiv:
                stack_count -= 2
                mov(assembler, edx, 0)
                mov(assembler, r10d, at(rbp, stack_base - 8 * (stack_count + 2))) 
                jit_div_by_zero_check(ctx, r10, get_instr_offset(instruction))
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                cdq(assembler)
                idiv(assembler, r10d)
                stack_count += 1
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .imul:
                mov(assembler, edx, 0)
                stack_count -= 2
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 2))) 
                mov(assembler, r10d, at(rbp, stack_base - 8 * (stack_count + 1))) 
                cdq(assembler)
                imul(assembler, rax, r10)
                stack_count += 1
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .ior:
                stack_count -= 2
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 2))) 
                or(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), eax)
                stack_count += 1
            case .ixor:
                stack_count -= 2
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 2))) 
                xor(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), eax)
                stack_count += 1
            case .iand:
                stack_count -= 2
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 2))) 
                and(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), eax)
                stack_count += 1
                
            case .iadd:
                stack_count -= 2
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 2))) 
                add(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), eax)
                stack_count += 1
            case .isub:
                stack_count -= 2
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 2))) 
                sub(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), eax)
                stack_count += 1
            case .iushr:
                stack_count -= 2
                mov(assembler, ecx, at(rbp, stack_base - 8 * (stack_count + 2))) 
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                and(assembler, ecx, 0b11111)
                shr_cl(assembler, eax)
                mov(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), eax) 
                stack_count += 1
            case .ishr:
                stack_count -= 2
                mov(assembler, ecx, at(rbp, stack_base - 8 * (stack_count + 2))) 
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                and(assembler, ecx, 0b11111)
                sar_cl(assembler, eax)
                mov(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), eax) 
                stack_count += 1
            case .lshr:
                stack_count -= 2
                mov(assembler, ecx, at(rbp, stack_base - 8 * (stack_count + 2))) 
                mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                and(assembler, ecx, 0b11111)
                sar_cl(assembler, eax)
                mov(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), rax) 
                stack_count += 1
            case .lushr:
                stack_count -= 2
                mov(assembler, ecx, at(rbp, stack_base - 8 * (stack_count + 2))) 
                mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                and(assembler, ecx, 0b11111)
                shr_cl(assembler, eax)
                mov(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), rax) 
                stack_count += 1

            case .ishl:
                stack_count -= 2
                mov(assembler, ecx, at(rbp, stack_base - 8 * (stack_count + 2))) 
                mov(assembler, eax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                and(assembler, ecx, 0b11111)
                shl_cl(assembler, eax)
                mov(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), eax) 
                stack_count += 1
            case .lcmp:
                stack_count -= 2
                mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 2))) 
                mov(assembler, rcx, at(rbp, stack_base - 8 * (stack_count + 1)))
                mov(assembler, rdx, 0)
                cmp(assembler, rcx, rax)
                cmove(assembler, rax, rdx)
                mov(assembler, rdx, 1)
                cmovg(assembler, rax, rdx)
                mov(assembler, rdx, -1)
                cmovl(assembler, rax, rdx)
                stack_count += 1
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)

            case .lshl:
                stack_count -= 2
                mov(assembler, rcx, at(rbp, stack_base - 8 * (stack_count + 2))) 
                mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                and(assembler, ecx, 0b111111)
                shl_cl(assembler, rax)
                mov(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), rax) 
                stack_count += 1
            case .ladd:
                stack_count -= 2
                mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 2))) 
                add(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), rax)
                stack_count += 1
            case .lsub:
                stack_count -= 2
                mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 2))) 
                sub(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), rax)
                stack_count += 1

            case .lmul:
                mov(assembler, edx, 0)
                stack_count -= 2
                mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 2))) 
                mov(assembler, r10, at(rbp, stack_base - 8 * (stack_count + 1))) 
                imul(assembler, r10)
                stack_count += 1
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .lor:
                stack_count -= 2
                mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 2))) 
                or(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), rax)
                stack_count += 1
            case .lxor:
                stack_count -= 2
                mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 2))) 
                xor(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), rax)
                stack_count += 1
            case .land:
                stack_count -= 2
                mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 2))) 
                and(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), rax)
                stack_count += 1
            case .ldiv:
                stack_count -= 2
                mov(assembler, edx, 0)
                mov(assembler, r10, at(rbp, stack_base - 8 * (stack_count + 2))) 
                jit_div_by_zero_check(ctx, r10, get_instr_offset(instruction))
                mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 1))) 
                idiv(assembler, r10)
                stack_count += 1
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)

            case .dneg:
                sign_mask := uint(0x8000000000000000)
                mov(assembler, rax, transmute(int)sign_mask)
                xor(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .fneg:
                sign_mask := u32(0x80000000)
                xor(assembler, at(rbp, stack_base - 8 * stack_count), transmute(i32)sign_mask)
            case .ineg:
                neg_m32(assembler, at(rbp, stack_base - 8 * stack_count))
            case .lneg:
                neg_m64(assembler, at(rbp, stack_base - 8 * stack_count))
            case .putstatic:
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                fldclass: ^Class = nil
                field := get_fieldrefconst_field(vm, method.parent.class_file, index, &fldclass).value.(^Field)
                jit_ensure_clinit_called(ctx, fldclass)
                mov(assembler, rax, at(rbp, stack_base - 8 * stack_count))
                mov(assembler, r10, transmute(int)&field.static_data)
                mov(assembler, at(r10), rax)
                stack_count -= 1
            case .getstatic:
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
            
                fldclass: ^Class = nil
                fieldres := get_fieldrefconst_field(vm, method.parent.class_file, index, &fldclass)
                jit_ensure_clinit_called(ctx, fldclass)
                field := fieldres.value.(^Field)
                
                mov(assembler, rax, transmute(int)&field.static_data)
                mov(assembler, rax, at(rax))
                stack_count += 1 
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .putfield:
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                fldclass: ^Class = nil
                field := get_fieldrefconst_field(vm, method.parent.class_file, index, &fldclass).value.(^Field)
                jit_ensure_clinit_called(ctx, fldclass)
                offset := field.offset
                assert(offset != 0)
                stack_count -= 2
                mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + 2)))
                mov(assembler, r10, at(rbp, stack_base - 8 * (stack_count + 1)))
                jit_null_check(ctx, r10, get_instr_offset(instruction))  
                mov(assembler, at(r10, field.offset), rax)
            case .getfield:
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                fldclass: ^Class = nil
                field := get_fieldrefconst_field(vm, method.parent.class_file, index, &fldclass).value.(^Field)
                jit_ensure_clinit_called(ctx, fldclass)
                offset := field.offset
                assert(offset != 0)
                mov(assembler, rax, at(rbp, stack_base - 8 * stack_count))
                jit_null_check(ctx, rax, get_instr_offset(instruction))  
                mov(assembler, rax, at(rax, offset))
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .ifne, .ifnonnull:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 1
                cmp(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), i32(0))
                jne(assembler, labels[start])
            case .ifeq, .ifnull:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 1
                cmp(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), i32(0))
                je(assembler, labels[start])
            case .ifle:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 1
                cmp(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), i32(0))
                jle(assembler, labels[start])
            case .iflt:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 1
                cmp(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), i32(0))
                jlt(assembler, labels[start])
            case .ifgt:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 1
                cmp(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), i32(0))
                jgt(assembler, labels[start])
            case .ifge:
                start := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                stack_count -= 1
                cmp(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), i32(0))
                jge(assembler, labels[start])
            case .aastore, .dastore:
                jit_array_store(ctx, instruction, 8)
            case .aaload, .daload:
                jit_array_load(ctx, instruction, 8)
            case .caload, .saload:
                jit_array_load(ctx, instruction, 2)
            case .castore, .sastore:
                jit_array_store(ctx, instruction, 2)
            case .baload:
                jit_array_load(ctx, instruction, 1)
            case .bastore:
                jit_array_store(ctx, instruction, 1)
            case .iaload:
                jit_array_load(ctx, instruction, 4)
            case .iastore, .fastore:
                jit_array_store(ctx, instruction, 4)

            case .d2i:
                cvttsd2si(assembler, eax, at(rbp, stack_base - 8 * stack_count))
                mov(assembler, at(rbp, stack_base - 8 * stack_count), eax)
            case .d2l:
                cvttsd2si(assembler, rax, at(rbp, stack_base - 8 * stack_count))
                mov(assembler, at(rbp, stack_base - 8 * stack_count), eax)
            case .l2d:
                cvtsi2sd_mem64(assembler, xmm0, at(rbp, stack_base - 8 * stack_count))
                movsd(assembler, at(rbp, stack_base - 8 * stack_count), xmm0)
            case .l2f:
                cvtsi2ss_mem64(assembler, xmm0, at(rbp, stack_base - 8 * stack_count))
                movsd(assembler, at(rbp, stack_base - 8 * stack_count), xmm0)
            case .l2i:
            case .i2l:
                mov(assembler, rax, at(rbp, stack_base - 8 * stack_count))
                mov(assembler, eax, eax)
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .i2c:
                and(assembler, at(rbp, stack_base - 8 * stack_count), 0xffff)
            case .i2b:
                and(assembler, at(rbp, stack_base - 8 * stack_count), i32(0xff))
            case .i2s:
                movsx_mem16(assembler, eax, at(rbp, stack_base - 8 * stack_count))
                mov(assembler, at(rbp, stack_base - 8 * stack_count), eax)
            case .i2d:
                cvtsi2sd_mem32(assembler, xmm0, at(rbp, stack_base - 8 * stack_count))
                movsd(assembler, at(rbp, stack_base - 8 * stack_count), xmm0)
            case .i2f:
                cvtsi2ss_mem32(assembler, xmm0, at(rbp, stack_base - 8 * stack_count))
                movsd(assembler, at(rbp, stack_base - 8 * stack_count), xmm0)
            case .f2i:
                cvttss2si(assembler, eax, at(rbp, stack_base - 8 * stack_count))
                mov(assembler, at(rbp, stack_base - 8 * stack_count), eax)
                movsd(assembler, at(rbp, stack_base - 8 * stack_count), xmm0)
            case .f2d:
                cvtss2sd(assembler, xmm0, at(rbp, stack_base - 8 * stack_count)) 
                movsd(assembler, at(rbp, stack_base - 8 * stack_count), xmm0)
            case .fdiv:
                stack_count -= 2
                movss(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 1)))
                divss(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 2)))
                stack_count += 1
                movss(assembler, at(rbp, stack_base - 8 * stack_count), xmm0)
            case .ddiv:
                stack_count -= 2
                movsd(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 1)))
                divsd(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 2)))
                stack_count += 1
                movsd(assembler, at(rbp, stack_base - 8 * stack_count), xmm0)
            case .fsub:
                stack_count -= 2
                movss(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 1)))
                subss(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 2)))
                stack_count += 1
                movss(assembler, at(rbp, stack_base - 8 * stack_count), xmm0)
            case .dsub:
                stack_count -= 2
                movsd(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 1)))
                subsd(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 2)))
                stack_count += 1
                movsd(assembler, at(rbp, stack_base - 8 * stack_count), xmm0)
            case .fmul:
                stack_count -= 2
                movss(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 2)))
                mulss(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 1)))
                stack_count += 1
                movss(assembler, at(rbp, stack_base - 8 * stack_count), xmm0)
            case .dmul:
                stack_count -= 2
                movsd(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 2)))
                mulsd(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 1)))
                stack_count += 1
                movsd(assembler, at(rbp, stack_base - 8 * stack_count), xmm0)
            case .fadd:
                stack_count -= 2
                movss(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 2)))
                addss(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 1)))
                movss(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), xmm0)
                stack_count += 1
            case .dadd:
                stack_count -= 2
                movsd(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 2)))
                addsd(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 1)))
                stack_count += 1
                movsd(assembler, at(rbp, stack_base - 8 * stack_count), xmm0)
            case .dcmpl:
                stack_count -= 2
                greater := create_label(assembler)
                less := create_label(assembler)
                equals := create_label(assembler)
                endofblock := create_label(assembler)
                movsd(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 1)))
                movsd(assembler, xmm1, at(rbp, stack_base - 8 * (stack_count + 2)))
                movsd(assembler, xmm2, xmm0)
                movsd(assembler, xmm3, xmm0)
                
                // NaN check
                cmpordsd(assembler, xmm2, xmm1)
                cvttss2si(assembler, eax, xmm2)
                cmp(assembler, eax, 0)
                je(assembler, less)

                cmpnlesd(assembler, xmm3, xmm1)
                cvttss2si(assembler, eax, xmm3)
                cmp(assembler, eax, 0)
                jne(assembler, greater)
                cmpltsd(assembler, xmm0, xmm1)
                cvttss2si(assembler, eax, xmm0)
                cmp(assembler, eax, 0)
                je(assembler, equals)
                set_label(assembler, less)
                movsx(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), -1)
                jmp(assembler, endofblock)
                set_label(assembler, greater)
                movsx(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), 1)
                jmp(assembler, endofblock)
                set_label(assembler, equals)
                movsx(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), 0)
                set_label(assembler, endofblock)
                stack_count += 1
            case .dcmpg:
                stack_count -= 2
                greater := create_label(assembler)
                less := create_label(assembler)
                equals := create_label(assembler)
                endofblock := create_label(assembler)
                movsd(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 1)))
                movsd(assembler, xmm1, at(rbp, stack_base - 8 * (stack_count + 2)))
                movsd(assembler, xmm2, xmm0)
                movsd(assembler, xmm3, xmm0)
                
                // NaN check
                cmpordsd(assembler, xmm2, xmm1)
                cvttss2si(assembler, eax, xmm2)
                cmp(assembler, eax, 0)
                je(assembler, greater)

                cmpnlesd(assembler, xmm3, xmm1)
                cvttss2si(assembler, eax, xmm3)
                cmp(assembler, eax, 0)
                jne(assembler, greater)
                cmpltsd(assembler, xmm0, xmm1)
                cvttss2si(assembler, eax, xmm0)
                cmp(assembler, eax, 0)
                je(assembler, equals)
                set_label(assembler, less)
                movsx(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), -1)
                jmp(assembler, endofblock)
                set_label(assembler, greater)
                movsx(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), 1)
                jmp(assembler, endofblock)
                set_label(assembler, equals)
                movsx(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), 0)
                set_label(assembler, endofblock)
                stack_count += 1
            case .fcmpl:
                stack_count -= 2
                greater := create_label(assembler)
                less := create_label(assembler)
                equals := create_label(assembler)
                endofblock := create_label(assembler)
                movss(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 1)))
                movss(assembler, xmm1, at(rbp, stack_base - 8 * (stack_count + 2)))
                movss(assembler, xmm2, xmm0)
                movss(assembler, xmm3, xmm0)
                
                // NaN check
                cmpordss(assembler, xmm2, xmm1)
                cvttss2si(assembler, eax, xmm2)
                cmp(assembler, eax, 0)
                je(assembler, less)

                cmpnless(assembler, xmm3, xmm1)
                cvttss2si(assembler, eax, xmm3)
                cmp(assembler, eax, 0)
                jne(assembler, greater)
                cmpltss(assembler, xmm0, xmm1)
                cvttss2si(assembler, eax, xmm0)
                cmp(assembler, eax, 0)
                je(assembler, equals)
                set_label(assembler, less)
                movsx(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), -1)
                jmp(assembler, endofblock)
                set_label(assembler, greater)
                movsx(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), 1)
                jmp(assembler, endofblock)
                set_label(assembler, equals)
                movsx(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), 0)
                set_label(assembler, endofblock)
                stack_count += 1
            case .fcmpg:
                stack_count -= 2
                greater := create_label(assembler)
                less := create_label(assembler)
                equals := create_label(assembler)
                endofblock := create_label(assembler)
                movss(assembler, xmm0, at(rbp, stack_base - 8 * (stack_count + 1)))
                movss(assembler, xmm1, at(rbp, stack_base - 8 * (stack_count + 2)))
                movss(assembler, xmm2, xmm0)
                movss(assembler, xmm3, xmm0)
                
                // NaN check
                cmpordss(assembler, xmm2, xmm1)
                cvttss2si(assembler, eax, xmm2)
                cmp(assembler, eax, 0)
                je(assembler, greater)

                cmpnless(assembler, xmm3, xmm1)
                cvttss2si(assembler, eax, xmm3)
                cmp(assembler, eax, 0)
                jne(assembler, greater)
                cmpltss(assembler, xmm0, xmm1)
                cvttss2si(assembler, eax, xmm0)
                cmp(assembler, eax, 0)
                je(assembler, equals)
                set_label(assembler, less)
                movsx(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), -1)
                jmp(assembler, endofblock)
                set_label(assembler, greater)
                movsx(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), 1)
                jmp(assembler, endofblock)
                set_label(assembler, equals)
                movsx(assembler, at(rbp, stack_base - 8 * (stack_count + 1)), 0)
                set_label(assembler, endofblock)
                stack_count += 1
            case .iinc:
                
                ops := instruction.(classparser.SimpleInstruction).operand.(classparser.TwoOperands)
                imm :i32= cast(i32)ops.op2
                if imm == 1 {
                    inc_m32(assembler, at(rbp, locals[ops.op1]))
                }
                else {
                    mov(assembler, rax, at(rbp, locals[ops.op1]))

                    addsx(assembler, rax, imm)
                    mov(assembler, at(rbp, locals[ops.op1]), rax)
                }
            case .anewarray:
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                mov(assembler, parameter_registers[0], transmute(int)vm)
                cls := get_class(vm, method.parent.class_file, index).value.(^Class)
                mov(assembler, parameter_registers[1], transmute(int)cls)
                mov(assembler, parameter_registers[2], at(rbp, stack_base - 8 * stack_count))
                lea(assembler, parameter_registers[3], at(rbp, stack_base - 8 * stack_count))
                mov(assembler, rax, transmute(int)gc_alloc_array)
                when ODIN_OS == .Windows { subsx(assembler, rsp, i32(32)) } 
                call(assembler, rax)
                when ODIN_OS == .Windows { addsx(assembler, rsp, i32(32)) } 
            case .newarray:
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                mov(assembler, reg_args[0], transmute(int)vm)
                typ := make_primitive(vm, array_type_primitives[index - 4], primitive_names[array_type_primitives[index - 4]], primitive_sizes[array_type_primitives[index - 4]])
                mov(assembler, reg_args[1], transmute(int)typ)
                mov(assembler, reg_args[2], at(rbp, stack_base - 8 * stack_count))
                lea(assembler, reg_args[3], at(rbp, stack_base - 8 * stack_count))
                mov(assembler, rax, transmute(int)gc_alloc_array)
                when ODIN_OS == .Windows { subsx(assembler, rsp, i32(32)) } 
                call(assembler, rax)
                when ODIN_OS == .Windows { addsx(assembler, rsp, i32(32)) } 
            case .new:
                stack_count += 1 
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                new_obj_class := get_class(vm, method.parent.class_file, index).value.(^Class)
                mov(assembler, reg_args[0], transmute(int)vm)
                mov(assembler, reg_args[1], transmute(int)new_obj_class)
                
                mov(assembler, reg_args[2], rbp)
                addsx(assembler, reg_args[2], i32(stack_base - 8 * stack_count))
                mov(assembler, reg_args[3], transmute(int)cast(int)-1)
                mov(assembler, rax, transmute(int)gc_alloc_object)
                when ODIN_OS == .Windows { subsx(assembler, rsp, i32(32)) } 
                call(assembler, rax)
                when ODIN_OS == .Windows { addsx(assembler, rsp, i32(32)) } 
            case .multianewarray:
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.TwoOperands).op1
                dimensions := cast(i32)instruction.(classparser.SimpleInstruction).operand.(classparser.TwoOperands).op2
                class := get_class(vm, method.parent.class_file, index).value.(^Class)
                stack_count -= dimensions
                elems_size := dimensions * 8
                if elems_size % 16 != 0 {
                    elems_size += 8
                }
                subsx(assembler, rsp, elems_size)
                mov(assembler, reg_args[2], rsp)
                for i in 1..=dimensions {
                    mov(assembler, rax, at(rbp, stack_base - 8 * (stack_count + i))) 
                    mov(assembler, at(reg_args[2], (i-1) * 8), rax)
                }
                stack_count += 1
                mov(assembler, reg_args[0], transmute(int)vm)
                mov(assembler, reg_args[1], transmute(int)class)
                mov(assembler, reg_args[3], rbp)
                addsx(assembler, reg_args[3], i32(stack_base - 8 * stack_count))
                mov(assembler, rax, transmute(int)gc_alloc_multiarray)
                when ODIN_OS == .Windows { subsx(assembler, rsp, i32(32)) } 
                call(assembler, rax)
                when ODIN_OS == .Windows { addsx(assembler, rsp, i32(32)) } 
                addsx(assembler, rsp, elems_size)
            case .dup_x1:
                mov(assembler, rax, at(rbp, stack_base - 8 * stack_count))
                stack_count -= 1
                mov(assembler, rcx, at(rbp, stack_base - 8 * stack_count))
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
                stack_count += 1
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rcx)
                stack_count += 1
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .dup_x2: // value1, value2, value3 -> value1, value3, value2, value1
                mov(assembler, rax, at(rbp, stack_base - 8 * stack_count))
                stack_count -= 1
                mov(assembler, rcx, at(rbp, stack_base - 8 * stack_count))
                stack_count -= 1
                mov(assembler, rdx, at(rbp, stack_base - 8 * stack_count))
                stack_count -= 1
                stack_count += 1
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
                stack_count += 1
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rdx)
                stack_count += 1
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rcx)
                stack_count += 1
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .dup:
                mov(assembler, rax, at(rbp, stack_base - 8 * stack_count))
                stack_count += 1
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .athrow:
                movsx(assembler, at(rbp, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, pc))), i32(get_instr_offset(instruction)))
                subsx(assembler, rsp, i32(16))
                mov(assembler, reg_args[0], transmute(int)vm)
                mov(assembler, reg_args[1], at(rbp, stack_base - 8 * stack_count)) 
                mov(assembler, reg_args[2], rsp)
                lea(assembler, reg_args[3], at(rsp, 8))
                mov(assembler, rax, transmute(int)throw_impl)
                when ODIN_OS == .Windows { subsx(assembler, rsp, i32(32)) } 
                call(assembler, rax)
                when ODIN_OS == .Windows { addsx(assembler, rsp, i32(32)) } 
                mov(assembler, rdi, at(rbp, stack_base - 8 * stack_count))
                mov(assembler, rbp, at(rsp))
                mov(assembler, r10, rbp)
                sub(assembler, r10, at(rsp, 8))
                mov(assembler, rsp, r10)
                jmp(assembler, rax)
            case .instanceof:
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                mov(assembler, parameter_registers[0], transmute(int)vm)
                mov(assembler, parameter_registers[1], transmute(int)get_class(vm, method.parent.class_file, index).value.(^Class))
                mov(assembler, parameter_registers[2], at(rbp, stack_base - 8 * stack_count))
                mov(assembler, rax, transmute(int)instanceof)
                when ODIN_OS == .Windows { subsx(assembler, rsp, 32) }
                call(assembler, rax)
                when ODIN_OS == .Windows { addsx(assembler, rsp, 32) }
                andsx(assembler, rax, i32(0xff))
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .checkcast:
                index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
                movsx(assembler, at(rbp, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, pc))), i32(get_instr_offset(instruction)))
                mov(assembler, parameter_registers[0], transmute(int)vm)
                mov(assembler, parameter_registers[1], transmute(int)get_class(vm, method.parent.class_file, index).value.(^Class))
                mov(assembler, parameter_registers[2], at(rbp, stack_base - 8 * stack_count))
                mov(assembler, rax, transmute(int)checkcast)
                when ODIN_OS == .Windows { subsx(assembler, rsp, 32) }
                call(assembler, rax)
                when ODIN_OS == .Windows { addsx(assembler, rsp, 32) }
            case .arraylength:
                mov(assembler, rax, at(rbp, stack_base - 8 * stack_count))
                jit_null_check(ctx, rax, get_instr_offset(instruction))
                mov(assembler, rax, at(rax, cast(i32)offset_of(ArrayHeader, length)))
                mov(assembler, at(rbp, stack_base - 8 * stack_count), rax)
            case .lookupswitch:
                table := instruction.(classparser.LookupSwitch)
                mov(assembler, rax, at(rbp, stack_base - 8 * stack_count))
                stack_count -= 1
                for offset in table.pairs {
                    cmp(assembler, eax, i32(offset.fst))
                    je(assembler, labels[offset.snd])
                }
                jmp(assembler, labels[table.default])
            case .tableswitch:
                table := instruction.(classparser.TableSwitch)
                mov(assembler, rax, at(rbp, stack_base - 8 * stack_count))
                stack_count -= 1
                mov(assembler, r10, transmute(int)table.low)
                cmp(assembler, rax, r10)
                jlt(assembler, labels[table.default])
                mov(assembler, r10, transmute(int)table.high)
                cmp(assembler, rax, r10)
                jgt(assembler, labels[table.default])
                subsx(assembler, rax, i32(table.low))
                mov(assembler, r10, 0)
                for offset in table.offsets {
                    cmp(assembler, rax, r10)
                    je(assembler, labels[offset])
                    addsx(assembler, r10, i32(1))
                }
                jmp(assembler, labels[table.default])
            case:
                fmt.println(instruction)
                panic("unimplemented")
        }
    }
} 
checkcast :: proc "c" (vm: ^VM, class: ^Class, object: ^ObjectHeader) {
    context = vm.ctx
    if(object == nil) {
        return
    }
    if !instanceof(vm, class, object) {
        message := fmt.aprintf("%s cannot be cast to %s", object.class.name, class.name)
        messageobj: ^ObjectHeader = nil
        gc_alloc_string(vm, message, &messageobj)
        delete(message)
        throw_exception(vm, "java/lang/ClassCastException", messageobj)
    }
}
instanceof :: proc "c" (vm: ^VM, class: ^Class, object: ^ObjectHeader) -> bool {
    context = vm.ctx
    return object != nil && is_subtype_of(object.class, class)
//     if(hasFlag(class.access_flags, classparser.ClassAccessFlags.Interface)) {
//         return does_implements_interface(object.class, class)      
//     }
//     else {
//         return class == object.class || is_subtype_of(object.class, class)
//     }
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
jit_div_by_zero_check :: proc(using ctx: ^JittingContext, reg: x86asm.Reg64, pc: int) {
    using x86asm
    oklabel := create_label(assembler)
    cmpsx(assembler, reg, i32(0))
    jne(assembler, oklabel)

    movsx(assembler, at(rbp, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, pc))), i32(pc))
    ariphexc := load_class(vm, "java/lang/ArithmeticException").value.(^Class)
    ctor := find_method(ariphexc, "<init>", "(Ljava/lang/String;)V")
    msg: ^ObjectHeader = nil
    gc_alloc_string(vm, "/ by zero", &msg)

    subsx(assembler, rsp, i32(16))
    mov(assembler, parameter_registers[0], transmute(int)vm)
    mov(assembler, parameter_registers[1], transmute(int)ariphexc)
    mov(assembler, parameter_registers[2], rsp)
    mov(assembler, parameter_registers[3], cast(int)-1)
    mov(assembler, rax, transmute(int)gc_alloc_object)
    when ODIN_OS == .Windows { subsx(assembler, rsp, i32(32)) }
    call(assembler, rax)
    when ODIN_OS == .Windows { addsx(assembler, rsp, i32(32)) }



    mov(assembler, parameter_registers[0], at(rsp))
    mov(assembler, parameter_registers[1], transmute(int)msg)
    mov(assembler, rax, transmute(int)&ctor.jitted_body)
    when ODIN_OS == .Windows { subsx(assembler, rsp, i32(32)) }
    call(assembler, at(rax))
    when ODIN_OS == .Windows { addsx(assembler, rsp, i32(32)) }

    mov(assembler, parameter_registers[0], transmute(int)vm)
    mov(assembler, parameter_registers[1], at(rsp))
    mov(assembler, parameter_registers[2], rsp)
    addsx(assembler, parameter_registers[2], i32(8))
    mov(assembler, rax, transmute(int)throw_impl)
    when ODIN_OS == .Windows { subsx(assembler, rsp, i32(32)) }
    call(assembler, rax)
    when ODIN_OS == .Windows { addsx(assembler, rsp, i32(32)) }
    mov(assembler, rdi, at(rsp))
    mov(assembler, rbp, at(rsp, 8))
    jmp(assembler, rax)
    set_label(assembler, oklabel)
    
}
jit_null_check :: proc(using ctx: ^JittingContext, reg: x86asm.Reg64, pc: int) {
    using x86asm
    oklabel := create_label(assembler)
    cmpsx(assembler, reg, i32(0))
    jne(assembler, oklabel)

    movsx(assembler, at(rbp, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, pc))), i32(pc))

    subsx(assembler, rsp, i32(16))
    mov(assembler, parameter_registers[0], transmute(int)vm)
    mov(assembler, parameter_registers[1], transmute(int)load_class(vm, "java/lang/NullPointerException").value.(^Class))
    mov(assembler, parameter_registers[2], rsp)
    mov(assembler, parameter_registers[3], cast(int)-1)
    mov(assembler, rax, transmute(int)gc_alloc_object)
    when ODIN_OS == .Windows { subsx(assembler, rsp, i32(32)) }
    call(assembler, rax)
    when ODIN_OS == .Windows { addsx(assembler, rsp, i32(32)) }
    mov(assembler, parameter_registers[0], transmute(int)vm)
    mov(assembler, parameter_registers[1], at(rsp))
    mov(assembler, parameter_registers[2], rsp)
    addsx(assembler, parameter_registers[2], i32(8))
    mov(assembler, rax, transmute(int)throw_impl)
    when ODIN_OS == .Windows { subsx(assembler, rsp, i32(32)) }
    call(assembler, rax)
    when ODIN_OS == .Windows { addsx(assembler, rsp, i32(32)) }
    mov(assembler, rdi, at(rsp))
    mov(assembler, rbp, at(rsp, 8))
    jmp(assembler, rax)
    set_label(assembler, oklabel)
    
}
jit_bounds_check :: proc(using ctx: ^JittingContext, array: x86asm.Reg64, index: x86asm.Reg32, pc: int) {
    using x86asm
    notoutofbounds := create_label(assembler)
    outofbounds := create_label(assembler)

    cmp(assembler, at(array, i32(offset_of(ArrayHeader, length))), index)
    jle(assembler, outofbounds)
    cmp(assembler, index, i32(0))
    jge(assembler, notoutofbounds)
    set_label(assembler, outofbounds)

    movsx(assembler, at(rbp, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, pc))), i32(pc))


    subsx(assembler, rsp, i32(16))

    mov(assembler, parameter_registers[0], transmute(int)vm)
    mov(assembler, parameter_registers[1], transmute(int)load_class(vm, "java/lang/ArrayIndexOutOfBoundsException").value.(^Class))
    mov(assembler, parameter_registers[2], rsp)
    mov(assembler, parameter_registers[3], transmute(int)cast(int)-1)
    mov(assembler, rax, transmute(int)gc_alloc_object)
    when ODIN_OS == .Windows { subsx(assembler, rsp, i32(32)) }
    call(assembler, rax)
    when ODIN_OS == .Windows { addsx(assembler, rsp, i32(32)) }
    mov(assembler, parameter_registers[0], transmute(int)vm)
    mov(assembler, parameter_registers[1], at(rsp))
    mov(assembler, parameter_registers[2], rsp)
    addsx(assembler, parameter_registers[2], i32(8))
    mov(assembler, rax, transmute(int)throw_impl)
    when ODIN_OS == .Windows { subsx(assembler, rsp, i32(32)) }
    call(assembler, rax)
    when ODIN_OS == .Windows { addsx(assembler, rsp, i32(32)) }
    mov(assembler, rdi, at(rsp))
    mov(assembler, rbp, at(rsp, 8))
    jmp(assembler, rax)
    set_label(assembler, notoutofbounds)
}
is_long_or_double_class :: proc(class: ^Class) -> bool {
    return class.name == "long" || class.name == "double"
}
is_long_or_double_stacktype :: proc(class: ^StackType) -> bool {
    
    return !class.is_null && (class.class.name == "long" || class.class.name == "double")
}
is_long_or_double :: proc { is_long_or_double_class, is_long_or_double_stacktype }
jit_invoke_dynamic :: proc(using ctx: ^JittingContext, instruction: classparser.Instruction) {
    using classparser
    using x86asm
//     int3(assembler)
    index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
    invokedynamicinfo := resolve_const(InvokeDynamicInfo, method.parent.class_file, index).(InvokeDynamicInfo)
    bootstrap_method := method.parent.class_file.bootstrap_methods[invokedynamicinfo.bootstrap_method_attr_index]
    methodhandle := method.parent.class_file.constant_pool[bootstrap_method.bootstrap_arguments[1] - 1].(classparser.MethodHandleInfo)
    targetmethodres := get_methodrefconst_method(vm, method.parent.class_file, int(methodhandle.reference_index))
    targetmethod : ^Method = nil
    if targetmethodres.is_err {
        targetmethod = get_interfacemethodrefconst_method(vm, method.parent.class_file, int(methodhandle.reference_index)).value.(^Method)
    }
    else {
        targetmethod = targetmethodres.value.(^Method)
    }
    name_and_type := resolve_name_and_type(method.parent.class_file, invokedynamicinfo.name_and_type_index).(NameAndTypeInfo)
    type := resolve_utf8(method.parent.class_file, name_and_type.descriptor_index)
    typename := type.(string)
    index_of_closing := strings.index_any(typename, ")")
    typename = strings.cut(typename, index_of_closing + 1)
//                 defer delete(typename)
    
    invoketype := load_class(vm, typename).value.(^Class)
    lambdaclass := load_lambda_class(vm, targetmethod, nil, nil, nil)
    target: ^Method = nil
    for &method in invoketype.methods {
        if !hasFlag(method.access_flags, MethodAccessFlags.Static) && hasFlag(method.access_flags, MethodAccessFlags.Abstract) {
            target = &method 
            break
        }
    }
    subsx(assembler, rsp, 16)
    mov(assembler, parameter_registers[0], transmute(int)vm)
    mov(assembler, parameter_registers[1], transmute(int)lambdaclass)
    mov(assembler, parameter_registers[2], rsp)
    movsx(assembler, parameter_registers[3], -1)
    when ODIN_OS == .Windows { subsx(assembler, rsp, 32) }
    mov(assembler, rax, transmute(int)gc_alloc_object)
    call(assembler, rax)
    when ODIN_OS == .Windows { addsx(assembler, rsp, 32) }
    mov(assembler, rcx, at(rsp))
    addsx(assembler, rsp, 16)
    closured :=  len(targetmethod.args) - len(target.args)
    fieldi := len(lambdaclass.instance_fields) - 1
    for fieldi >= 0 {
        mov(assembler, rax, at(rbp, stack_base - 8 * stack_count))
        mov(assembler, at(rcx, lambdaclass.instance_fields[fieldi].offset), rax)
        stack_count -= 1
        fieldi -= 1
    }
    stack_count += 1
    mov(assembler, at(rbp, stack_base - 8 * stack_count), rcx)
}

jit_invoke_static :: proc(using ctx: ^JittingContext, instruction: classparser.Instruction) {
    index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op
    target := get_methodrefconst_method(vm, method.parent.class_file, index).value.(^Method)     
    jit_ensure_clinit_called(ctx, target.parent)
    jit_invoke_static_impl(ctx, target)
}
jit_invoke_interface:: proc(using ctx: ^JittingContext, instruction: classparser.Instruction) {
    index := instruction.(classparser.SimpleInstruction).operand.(classparser.TwoOperands).op1
    target_method := get_interface_method(vm, ctx.method.parent.class_file, index).value.(^Method)
    jit_invoke_method(ctx, target_method, instruction)
}
jit_invoke_special :: proc(using ctx: ^JittingContext, instruction: classparser.Instruction) {
    index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op 
    target_method := get_methodrefconst_method(vm, ctx.method.parent.class_file, index).value.(^Method)
    jit_ensure_clinit_called(ctx, target_method.parent)
    jit_invoke_method(ctx, target_method, instruction, false)
}
jit_invoke_virtual :: proc(using ctx: ^JittingContext, instruction: classparser.Instruction) {
    index := instruction.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op 
    target_method := get_methodrefconst_method(vm, ctx.method.parent.class_file, index).value.(^Method)
    jit_ensure_clinit_called(ctx, target_method.parent)
    jit_invoke_method(ctx, target_method, instruction)
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
    using classparser
    context = vm.ctx
    if object == nil {
        throw_NullPointerException(vm)
        return nil
    }
    found :^Method= nil
    class := object.class
    for found == nil {
        if class == nil {
            if hasFlag(target.parent.access_flags, ClassAccessFlags.Interface) {
                if hasFlag(target.access_flags, MethodAccessFlags.Abstract) {
                    throw_exception_string(vm, "java/lang/AbstractMethodError", "")
                }   
                return &target.jitted_body
            }
            fmt.println(is_subtype_of(object.class, target.parent))
            print_flags(target.parent.access_flags)
            fmt.println("\n", target.parent.name)
            print_flags(target.access_flags)
            fmt.println()
            fmt.println(target.name)
            fmt.println(object.class.name)
            fmt.println(target.parent.name)
            print_stack_trace()
            fmt.println(transmute(^int)object)
            throw_exception_string(vm, "java/lang/AbstractMethodError", "")
        }
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
find_method_virtual :: proc(class: ^Class, name: string, descriptor: string) -> ^Method {
    class := class
    for class != nil {
        for &method in class.methods {
            if method.name == name && method.descriptor == descriptor {
                return &method
            }
        }
        class = class.super_class
    }
    return nil
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
    push(assembler, rbp)
    mov(assembler, rbp, rsp)
    subsx(assembler, rsp, i32(size_of(StackEntry)))
    indices := jit_prepare_locals_indices(method, cb)
    stack_size := jit_prepare_locals(method, indices, assembler)

    mov(assembler, rax, transmute(int)method)
    mov(assembler, at(rbp, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, method))), rax)
    movsx(assembler, at(rbp, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, pc))), i32(0))
    mov(assembler, at(rbp, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, rbp))), rbp)
    movsx(assembler, at(rbp, ((-cast(i32)size_of(StackEntry)) + cast(i32)offset_of(StackEntry, size))), i32(stack_size + size_of(StackEntry)))
    mov(assembler, rax, transmute(int)stack_trace_push)
    mov(assembler, ODIN_OS == .Windows ? rcx : rdi, rbp)
    subsx(assembler, ODIN_OS == .Windows ? rcx : rdi, i32(32))
    when ODIN_OS == .Windows { subsx(assembler, rsp, i32(32)) }
    call(assembler, rax)
    when ODIN_OS == .Windows { addsx(assembler, rsp, i32(32)) }
    return indices
}
stacktrace := make([dynamic]^StackEntry)
stack_trace_push :: proc(stack_entry: ^StackEntry) {
     //for i in 0..<len(stacktrace) {
         //fmt.print(' ')
     //}
     //fmt.println("entered", stack_entry.method.name, stack_entry.method.descriptor, stack_entry.method.parent.name)
    append(&stacktrace, stack_entry)
}
stack_trace_pop :: proc "c" (vm: ^VM) -> ^StackEntry {
    context = vm.ctx
    res := stacktrace[len(stacktrace) - 1] 
     //for i in 0..<len(stacktrace)-1 {
         //fmt.print(' ')
     //}
     //fmt.println("left   ", res.method.name, res.method.parent.name)
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
    size: int,
}

jit_ensure_clinit_called_body :: proc "c" (vm: ^VM, class: ^Class, initializer: ^Method) {
    context = vm.ctx
    if class.super_class != nil && !class.super_class.class_initializer_called {
        parent_initializer := find_method(class.super_class, "<clinit>", "()V")
        if parent_initializer != nil {
            jit_ensure_clinit_called_body(vm, class.super_class, parent_initializer)
        }
    }
    if !class.class_initializer_called {
        class.class_initializer_called = true
        (transmute(proc "c" ())initializer.jitted_body)()
    }
}

