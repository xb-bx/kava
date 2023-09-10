package vm
import "kava:classparser"
import "kava:shared"
import "core:slice"
import "core:fmt"
import "core:os"

CodeBlock :: struct {
    start: int,
    end: int,
    stack_at_start: ^TypeStack,
    code: []classparser.Instruction,
    locals: []^Class,
    visited: bool,
    is_exception_handler: bool,
}
VerificationError :: struct {
    msg: string,
    method: ^Method,
    instruction: classparser.Instruction,
}
get_instr_opcode :: proc(instr: classparser.Instruction) -> classparser.Opcode {
    using classparser
    switch in instr {
        case SimpleInstruction:
            return instr.(SimpleInstruction).opcode
        case TableSwitch:
            return instr.(TableSwitch).opcode
        case LookupSwitch:
            return instr.(LookupSwitch).opcode
    }
    return Opcode.nop
}
get_instr_offset :: proc(instr: classparser.Instruction) -> int {
    using classparser
    switch in instr {
        case SimpleInstruction:
            return instr.(SimpleInstruction).offset
        case TableSwitch:
            return instr.(TableSwitch).offset
        case LookupSwitch:
            return instr.(LookupSwitch).offset
    }
    return -1
}
split_instructions_by_byteoffset :: proc(instructions: []classparser.Instruction, start: int, end: int, inclusive_end: bool = false) -> []classparser.Instruction {
    starti := -1
    endi := -1
    for instr,i  in instructions {
        if starti == -1 {
            if get_instr_offset(instr) >= start {
                starti = i
            }        
        }
        else if endi == -1 {
            if get_instr_offset(instr) == end {
                endi = i
            }
        }
        else {
            break
        }
    }
//     fmt.println(start, end, starti, endi)    
    if inclusive_end {
        if endi < starti {
            endi = starti
        }
        return instructions[starti:endi + 1]
    }
    else {
        if endi < starti {
            endi = starti + 1
        }
        return instructions[starti:endi]
    }
}
locals_equal :: proc(local1: []^Class, locals2: []^Class) -> bool {
//     for local, i in local1 {
//         local2 := locals2[i]
//         if local == nil || local2 == nil {
//             continue
//         }
//         if local != local2 {
//             return false
//         }
//     } 
    return true
}
split_method_into_codeblocks :: proc(vm: ^VM, method: ^Method) -> shared.Result([]CodeBlock, VerificationError) {
    using classparser
    using shared 
    assert(method.code != nil)
    blocks := find_method_block_indices(vm, method)
    codeattr := method.code.(CodeAttribute)
    method.max_locals = cast(int)codeattr.max_locals
    instructions := codeattr.code
    res := make([]CodeBlock, len(blocks) - 1) 
    if len(blocks) == 2 {
        res[0] = CodeBlock {
            start = 0,
            end = blocks[1],
            code = instructions,
            stack_at_start = nil,
            locals = make([]^Class, method.max_locals),
            visited = false,
        }
    }
    else {
        blocki := 0
        start := 0
        i := 0
        for blocki < len(blocks) - 1 {
            instr,index := find_instr_by_offset(instructions, blocks[blocki])
            startindex := index
            for index < len(instructions) {
                nextinstr := instructions[index]
                off := get_instr_offset(nextinstr)
                if off >= blocks[blocki + 1] {
                    break
                }
                index += 1
            }
            res[blocki] = CodeBlock {
                start = start,
                end = blocks[blocki + 1],
                code = instructions[startindex:index],
                locals = make([]^Class, method.max_locals),
                stack_at_start = nil,
                visited = false,
            }
            start = blocks[blocki + 1]
            blocki += 1
        }
    }
    if codeattr.max_stack == 0 {
        res[0].stack_at_start = new(TypeStack)
        res[0].stack_at_start.cap = 0
    }
    else {
        res[0].stack_at_start = new_clone(make_stack(cast(int)codeattr.max_stack))
    }
    if !hasFlag(method.access_flags, MethodAccessFlags.Static) {
        res[0].locals[0] = method.parent
        for arg, i in method.args {
            res[0].locals[i + 1] = arg
        }
    }
    else {
        for arg, i in method.args {
            res[0].locals[i] = arg
        }
    }
    for exception in method.code.(CodeAttribute).exception_table {
        cb := find_codeblock_by_start(res, cast(int)exception.handler_pc)
        class := get_class(vm, method.parent.class_file, cast(int)exception.catch_type)
        if class.is_err {
            return Err([]CodeBlock, verification_error(class.error.(string), method, {}))
        }
        cb.stack_at_start = new_clone(make_stack(cast(int)codeattr.max_stack))
        cb.is_exception_handler = true
        stack_push(cb.stack_at_start, class.value.(^Class))
    }
    err := calculate_stack(vm, &res[0], res, method) 
    for exception in method.code.(CodeAttribute).exception_table {
        cb := find_codeblock_by_start(res, cast(int)exception.handler_pc)
        if !cb.visited {
            err := calculate_stack(vm, cb, res, method)
            if err != nil {
                return Err([]CodeBlock, err.(VerificationError))
            }
        } 
    }

    if err != nil {
        return Err([]CodeBlock, err.(VerificationError))
    }
    return Ok(VerificationError, res)
}
print_verification_error :: proc(err: VerificationError) {
    fmt.printf("%s at (%s@%i) at %s.%s:%s\n", err.msg, get_instr_opcode(err.instruction), get_instr_offset(err.instruction), err.method.parent.name, err.method.name, err.method.descriptor)
} 
find_instr_by_offset :: proc(instructions: []classparser.Instruction, off: int) -> (^classparser.Instruction, int) {
    for &instr, index in instructions {
        if get_instr_offset(instr) == off {
            return &instr, index
        }
    }


    return nil, 0
}
get_methodrefconst_method :: proc(vm: ^VM, classfile: ^classparser.ClassFile, index: int) -> shared.Result(^Method, string) {
    using shared
    using classparser
    methodr := resolve_methodref(classfile, cast(u16)index)
    if methodr == nil {
        return Err(^Method, "Invalid bytecode")
    }
    methodref := methodr.(MethodRefInfo)
    class_name := resolve_class_name(classfile, methodref.class_index)
    if class_name == nil {
        return Err(^Method, "Invalid bytecode")
    }
    name_and_type := resolve_name_and_type(classfile, methodref.name_and_type_index)
    if name_and_type == nil {
        return Err(^Method, "Invalid bytecode")
    }
    name := resolve_utf8(classfile, name_and_type.(NameAndTypeInfo).name_index)
    if name == nil {
        return Err(^Method, "Invalid bytecode")
    }

    descriptor := resolve_utf8(classfile, name_and_type.(NameAndTypeInfo).descriptor_index)
    if descriptor == nil {
        return Err(^Method, "Invalid bytecode")
    }
    type := load_class(vm, class_name.(string))
    if type.is_err {
        return Err(^Method, type.error.(string))
    }    
    method := find_method_by_name_and_descriptor(type.value.(^Class), name.(string), descriptor.(string))
    if method == nil {
        return Err(^Method, fmt.aprintf("Failed to find method %s.%s:%s", class_name.(string), name.(string), descriptor.(string)))
    }
    return Ok(string, method) 
}
get_fieldrefconst_field :: proc(vm: ^VM, classfile: ^classparser.ClassFile, index: int) -> shared.Result(^Field, string) {
    using shared
    using classparser
    fieldr := resolve_field(classfile, cast(u16)index)
    if fieldr == nil {
        return Err(^Field, "Invalid bytecode")
    }
    field := fieldr.(FieldRefInfo)
    typename := resolve_class_name(classfile, field.class_index)
    if typename == nil {
        return Err(^Field, "Invalid bytecode")
    }
    name_and_type := resolve_name_and_type(classfile, field.name_and_type_index)
    if name_and_type == nil {
        return Err(^Field, "Invalid bytecode")
    }
    field_name_mb := resolve_utf8(classfile, name_and_type.(NameAndTypeInfo).name_index)
    if field_name_mb == nil {
        return Err(^Field, "Invalid bytecode")
    }
    field_name := field_name_mb.(string)
    type := load_class(vm, typename.(string))
    if type.is_err {
        return Err(^Field, type.error.(string))
    }    
    class := type.value.(^Class)
    for &clfield in class.fields {
        if clfield.name == field_name {
            return Ok(string, &clfield)
        }
    }
    return Err(^Field, fmt.aprintf("Invalid bytecode. Could not find field %s", field_name))
}
get_fieldrefconst_class :: proc(vm: ^VM, classfile: ^classparser.ClassFile, index: int) -> shared.Result(^Class, string) {
    using shared
    using classparser
    fieldr := resolve_field(classfile, cast(u16)index)
    if fieldr == nil {
        return Err(^Class, "Invalid bytecode")
    }
    field := fieldr.(FieldRefInfo)
    typename := resolve_class_name(classfile, field.class_index)
    if typename == nil {
        return Err(^Class, "Invalid bytecode")
    }
    type := load_class(vm, typename.(string))
    if type.is_err {
        return type
    }    
    return type
}
get_fieldrefconst_type :: proc(vm: ^VM, classfile: ^classparser.ClassFile, index: int) -> shared.Result(^Class, string) {
    using shared
    using classparser
    fieldr := resolve_field(classfile, cast(u16)index)
    if fieldr == nil {
        return Err(^Class, "Invalid bytecode")
    }
    field := fieldr.(FieldRefInfo)
    typename := resolve_type_from_name_and_type(classfile, field.name_and_type_index)
    if typename == nil {
        return Err(^Class, "Invalid bytecode")
    }
    type := load_class(vm, typename.(string))
    if type.is_err {
        return type
    }    
    return type
}
type_is_integer :: proc(typ: ^Class) -> bool {
    if typ.class_type != ClassType.Primitive {
        return false
    }
    return typ.primitive == PrimitiveType.Int ||  typ.primitive == PrimitiveType.Byte || typ.primitive == PrimitiveType.Short || typ.primitive == PrimitiveType.Long || typ.primitive == PrimitiveType.Boolean || typ.primitive == PrimitiveType.Char 
}
does_implements_interface :: proc(class: ^Class, interface: ^Class) -> bool {
    for iface in class.interfaces {
        if iface == interface {
            return true
        }
    }
    if class.super_class == nil {
        return false
    }
    return does_implements_interface(class.super_class, interface) 
}
is_stacktype_subtype_of :: proc(subtype: ^StackType, parent: ^Class) -> bool {
    if subtype.is_null {
        return true
    }
    else {
        return is_subtype_of(subtype.class, parent)        
    }
}
is_subtype_of :: proc(subtype: ^Class, parent: ^Class) -> bool {
    if subtype.super_class == parent {
        return true
    }
    else if subtype.super_class != nil {
        return is_subtype_of(subtype.super_class, parent)
    }
    return false
}
is_stacktype_array_of :: proc(array_class: ^StackType, elem_class: ^Class) -> bool {
    return array_class.is_null || is_array_of(array_class.class, elem_class)
}
is_array_of :: proc(array_class: ^Class, elem_class: ^Class) -> bool {
    return array_class.class_type == ClassType.Array && (array_class.underlaying == elem_class || (type_is_integer(elem_class) && type_is_integer(array_class.underlaying))  || is_subtype_of(array_class.underlaying, elem_class))
}
is_reference_type :: proc(vm: ^VM, type: ^Class) -> bool {
    return type == vm.object || is_subtype_of(type, vm.object)
}
print_codeblock :: proc(cb: ^CodeBlock, class: ^Class) {
    fmt.printf("start: %i end: %i\n", cb.start, cb.end)

    if cb.stack_at_start != nil {
        fmt.printf("stack: ")
        for typ in cb.stack_at_start.types {
            if typ.class != nil {
                fmt.printf("%s ", typ.class.name)
            }
        }
        fmt.println()
    }
    for instr in cb.code {
        print_instruction_with_const(instr, os.stdout, class.class_file)
    }
    
}
verification_error :: proc(msg: string, method: ^Method, instr: classparser.Instruction) -> VerificationError {
    return VerificationError {
        msg = msg,
        method = method,
        instruction = instr,
    }
}
print_stack :: proc(stack: ^TypeStack) {
    for i in 0..<stack.count {
        fmt.printf("%s ", stack.types[i].class.name)
    }
    fmt.println()
}
calculate_stack :: proc(vm: ^VM, cb: ^CodeBlock, cblocks: []CodeBlock, this_method: ^Method) -> Maybe(VerificationError) {
    using classparser
    if cb.visited == true {
        return nil
    }
    cb.visited = true
    stack := new_clone(copy_stack(cb.stack_at_start^))
    locals := slice.clone(cb.locals)
    i := 0
    canEscape := true
    for i < len(cb.code) {
        instr := cb.code[i]
        i += 1
        #partial switch get_instr_opcode(instr) {
            case .pop:
                if stack.count == 0 {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                stack_pop(stack)
            case .pop2:
                if stack.count == 0 {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                typ := stack_pop_class(stack)
                if is_long_or_double(typ) {
                    simple := &cb.code[i - 1].(classparser.SimpleInstruction)  
                    simple.opcode = .pop
                } else {
                    if stack.count == 0 {
                        return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                    }
                    stack_pop(stack)
                }
            case .aconst_null:
                if !stack_push(stack, vm.object, true) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }
            case .bipush, .sipush:
                if !stack_push(stack, vm.classes["int"]) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }
            case .getstatic:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                type := get_fieldrefconst_type(vm, this_method.parent.class_file, index)
                if type.is_err {
                    return verification_error(type.error.(string), this_method, instr)
                }
                if !stack_push(stack, type.value.(^Class)) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }
                
            case .putstatic:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                type := get_fieldrefconst_type(vm, this_method.parent.class_file, index)
                if type.is_err {
                    return verification_error(type.error.(string), this_method, instr)
                }
                typ := stack_pop(stack)
                if typ == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if type.value.(^Class) != typ.class && !is_stacktype_subtype_of(typ, type.value.(^Class)) {
                    return verification_error("Invalid bytecode. Wrong value type", this_method, instr)
                }
            case .putfield:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                type := get_fieldrefconst_type(vm, this_method.parent.class_file, index)
                if type.is_err {
                    return verification_error(type.error.(string), this_method, instr)
                }
                if stack.count < 2 {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                typ := stack_pop(stack)
                fieldtyperes := get_fieldrefconst_type(vm, this_method.parent.class_file, index)
                if fieldtyperes.is_err {
                    return verification_error(fieldtyperes.error.(string), this_method, instr)
                }
                fieldtype := fieldtyperes.value.(^Class)
                containingType := stack_pop(stack)
                if typ.class != fieldtype && (!is_stacktype_subtype_of(typ, fieldtype)) {
                    fmt.println(typ.class.name, containingType.class.name)
                    panic("Invalid bytecode. Wrong instance type")                   
//                     return verification_error("Invalid bytecode. Wrong instance type", this_method, instr)
                }
            case .getfield:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                type := get_fieldrefconst_type(vm, this_method.parent.class_file, index)
                if type.is_err {
                    return verification_error(type.error.(string), this_method, instr)
                }
                typ := stack_pop(stack)
                if typ == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                containingType := get_fieldrefconst_class(vm, this_method.parent.class_file, index)
                if containingType.is_err {
                    return verification_error(containingType.error.(string), this_method, instr)
                }
                if typ.class != containingType.value.(^Class) && (!is_stacktype_subtype_of(typ, containingType.value.(^Class))) {
                    return verification_error("Invalid bytecode. Wrong instance type", this_method, instr)
                }
                if !stack_push(stack, type.value.(^Class)) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }
            case .astore:
                t := stack_pop(stack)
                if t == nil || !is_reference_type(vm, t.class) {
                    return verification_error("Invalid bytecode. Expected reference-type", this_method, instr)
                }
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                if locals[index] == nil {
                    locals[index] = t.class
                }
                else if !is_stacktype_subtype_of(t, locals[index]) && t.class != locals[index] {
                    return verification_error("Invalid bytecode. Wrong value type", this_method, instr)
                }
            case .dstore:
                t := stack_pop_class(stack)
                if t == nil || t.name != "double" {
                    return verification_error("Invalid bytecode. Expected integer on stack before istore operation", this_method, instr)
                }
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                if locals[index] == nil {
                    locals[index] = t
                }
            case .dload:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                if index >= len(locals) || locals[index].name != "double" {
                    return verification_error("Invalid bytecode. Expected integer local variable", this_method, instr)
                }
                stack_push(stack, locals[index])
            case .lstore:
                t := stack_pop_class(stack)
                if t == nil || (t != vm.classes["long"] && !type_is_integer(t)) {
                    return verification_error("Invalid bytecode. Expected integer on stack before lstore operation", this_method, instr)
                }
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                if locals[index] == nil {
                    locals[index] = vm.classes["long"]
                }
            case .istore:
                t := stack_pop_class(stack)
                if t == nil || !type_is_integer(t) {
                    return verification_error("Invalid bytecode. Expected integer on stack before istore operation", this_method, instr)
                }
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                if locals[index] == nil {
                    locals[index] = t
                }
            case .iload:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                if index >= len(locals) {
                    return verification_error("Invalid bytecode. Expected integer local variable", this_method, instr)
                }
                if locals[index] == nil {
                    locals[index] = vm.classes["int"]
                }
                else if !type_is_integer(locals[index]) {
                    return verification_error("Invalid bytecode. Expected integer local variable", this_method, instr)
                }
                stack_push(stack, locals[index])
            case .lload:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                if index >= len(locals) || locals[index] != vm.classes["long"] {
                    return verification_error("Invalid bytecode. Expected long local variable", this_method, instr)
                }
                stack_push(stack, locals[index])
            case .aload:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                if index >= len(locals) || (locals[index] != vm.object &&  !is_subtype_of(locals[index], vm.object)) {
                    return verification_error("Invalid bytecode. Expected reference-type local variable", this_method, instr)
                }
                stack_push(stack, locals[index])
                
            case .tableswitch:
                canEscape = false
                t := stack_pop_class(stack) 
                if t == nil || !type_is_integer(t) {
                    return verification_error("Invalid bytecode. Expected integer on stack before istore operation", this_method, instr)
                }
                table := instr.(classparser.TableSwitch)
                for offset in table.offsets {
                    block := find_codeblock_by_start(cblocks, offset)         
                    if block == nil {
                        return verification_error("Invalid bytecode. Invalid jump offset", this_method, instr)
                    }
                    if block.stack_at_start == nil {
                        block.stack_at_start = new_clone(copy_stack(stack^))
                        block.locals = slice.clone(locals)
                        res := calculate_stack(vm, block, cblocks, this_method)
                        if res != nil {
                            return res
                        }
                    }
                    else if !stack_eq(block.stack_at_start, stack) || !locals_equal(locals, block.locals)  {
                        return verification_error("Invalid bytecode. Inconsistent stack", this_method, instr)
                    }
                }
                default_block := find_codeblock_by_start(cblocks, table.default)
                if default_block == nil {
                    return verification_error("Invalid bytecode. Invalid jump offset", this_method, instr)
                }
                if default_block.stack_at_start == nil {
                    default_block.stack_at_start = new_clone(copy_stack(stack^))
                    default_block.locals = slice.clone(locals)
                    
                    res := calculate_stack(vm, default_block, cblocks, this_method)
                    if res != nil {
                        return res
                    }
                }
                else if !stack_eq(default_block.stack_at_start, stack) || !locals_equal(locals, default_block.locals)  {
                    return verification_error("Invalid bytecode. Inconsistent stack", this_method, instr)
                }
            case .ldc2_w:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                typ := get_constant_type(vm, this_method.parent.class_file, index)
                if typ.is_err {
                    return verification_error(typ.error.(string), this_method, instr)
                }
                if !stack_push(stack, typ.value.(^Class)) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }
            case .ldc:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                typ := get_constant_type(vm, this_method.parent.class_file, index)
                if typ.is_err {
                    return verification_error(typ.error.(string), this_method, instr)
                }
                if !stack_push(stack, typ.value.(^Class)) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }
            case .anewarray:
                elems := stack_pop_class(stack)
                if elems == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if !type_is_integer(elems) {
                    return verification_error("Invalid bytecode. Expected integer value", this_method, instr)
                }
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                typ := get_class(vm, this_method.parent.class_file, index)
                if typ.is_err {
                    return verification_error(typ.error.(string), this_method, instr)
                }
                stack_push(stack, make_array_type(vm, typ.value.(^Class)))
            case .newarray:
                elems := stack_pop_class(stack)
                if elems == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if !type_is_integer(elems) {
                    return verification_error("Invalid bytecode. Expected integer value", this_method, instr)
                }
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                typ := make_primitive(vm, array_type_primitives[index - 4], primitive_names[array_type_primitives[index - 4]], primitive_sizes[array_type_primitives[index - 4]])
                stack_push(stack, make_array_type(vm, typ))
            case .new:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                typ := get_class(vm, this_method.parent.class_file, index)
                if typ.is_err {
                    return verification_error(typ.error.(string), this_method, instr)
                }
                if typ.value.(^Class) != vm.object && !is_subtype_of(typ.value.(^Class), vm.object) {
                    return verification_error("Invalid bytecode. Expected reference type", this_method, instr)
                }
                if !stack_push(stack, typ.value.(^Class)) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                } 
            case .instanceof:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                typ := get_class(vm, this_method.parent.class_file, index)
                if typ.is_err {
                    return verification_error(typ.error.(string), this_method, instr)
                }
                if typ.value.(^Class) != vm.object && !is_subtype_of(typ.value.(^Class), vm.object) {
                    return verification_error("Invalid bytecode. Expected reference type", this_method, instr)
                }
                instance := stack_pop(stack)
                if instance == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if !is_reference_type(vm, instance.class) {
                    return verification_error("Invalid bytecode. Expected reference type", this_method, instr)
                }
                if !stack_push(stack, vm.classes["boolean"]) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                } 
            case .checkcast:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                typ := get_class(vm, this_method.parent.class_file, index)
                if typ.is_err {
                    return verification_error(typ.error.(string), this_method, instr)
                }
                if typ.value.(^Class) != vm.object && !is_subtype_of(typ.value.(^Class), vm.object) {
                    return verification_error("Invalid bytecode. Expected reference type", this_method, instr)
                }
                instance := stack_pop(stack)
                if instance == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if !is_reference_type(vm, instance.class) {
                    panic("")
//                     return verification_error("Invalid bytecode. Expected reference type", this_method, instr)
                }
                if !stack_push(stack, typ.value.(^Class)) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                } 
                
            case .iastore:
                if stack.count < 3 {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                value := stack_pop_class(stack)
                index := stack_pop_class(stack)
                array := stack_pop(stack)
                if !type_is_integer(value) {
                    return verification_error("Invalid bytecode. value must be reference type", this_method, instr)
                }
                if !type_is_integer(index) {
                    return verification_error("Invalid bytecode. Index must be integer", this_method, instr)
                }
                if !is_stacktype_array_of(array, value) {
                    return verification_error("Invalid bytecode. Expected array of integers", this_method, instr)
                }
            case .bastore:
                if stack.count < 3 {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                value := stack_pop_class(stack)
                index := stack_pop_class(stack)
                array := stack_pop(stack)
                if !type_is_integer(value) {
                    return verification_error("Invalid bytecode. value must be reference type", this_method, instr)
                }
                if !type_is_integer(index) {
                    return verification_error("Invalid bytecode. Index must be integer", this_method, instr)
                }
                if !is_stacktype_array_of(array, value) {
                    return verification_error("Invalid bytecode. Expected array of bytes", this_method, instr)
                }
            case .castore:
                if stack.count < 3 {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                value := stack_pop_class(stack)
                index := stack_pop_class(stack)
                array := stack_pop(stack)
                if !type_is_integer(value) {
                    return verification_error("Invalid bytecode. value must be reference type", this_method, instr)
                }
                if !type_is_integer(index) {
                    return verification_error("Invalid bytecode. Index must be integer", this_method, instr)
                }
                if !is_stacktype_array_of(array, value) {
                    return verification_error("Invalid bytecode. Expected array of chars", this_method, instr)
                }
            case .aastore:
                if stack.count < 3 {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                value := stack_pop(stack)
                index := stack_pop_class(stack)
                array := stack_pop(stack)
                if !is_stacktype_subtype_of(value, vm.object) {
                    return verification_error("Invalid bytecode. value must be reference type", this_method, instr)
                }
                if !type_is_integer(index) {
                    return verification_error("Invalid bytecode. Index must be integer", this_method, instr)
                }
                if !is_stacktype_array_of(array, value.class) {
                    return verification_error("Invalid bytecode. Index must be integer", this_method, instr)
                }
            case ._return:
                if this_method.ret_type != vm.classes["void"] {
                    return verification_error("Invalid bytecode. Cannot return void from method", this_method, instr)
                }
                canEscape = false


            case .dreturn:
                ret_type := stack_pop_class(stack)
                if ret_type == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack1", this_method, instr)
                }
                if ret_type != this_method.ret_type || ret_type != vm.classes["double"] {
                    return verification_error("Invalid bytecode. Wrong return type", this_method, instr)
                }
                canEscape = false
            case .ireturn:
                ret_type := stack_pop_class(stack)
                if ret_type == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack1", this_method, instr)
                }
                if ret_type != this_method.ret_type && !type_is_integer(ret_type) {
                    return verification_error("Invalid bytecode. Wrong return type", this_method, instr)
                }
                canEscape = false
            case .areturn:
                ret_type := stack_pop(stack)
                if ret_type == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if ret_type.class != this_method.ret_type && !is_stacktype_subtype_of(ret_type, this_method.ret_type)  {
                    return verification_error("Invalid bytecode. Wrong return type", this_method, instr)
                }
                canEscape = false
            case .athrow:
                exc_type := stack_pop(stack)
                if exc_type == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if exc_type.class != vm.classes["java/lang/Throwable"] && !is_stacktype_subtype_of(exc_type, vm.classes["java/lang/Throwable"])  {
                    return verification_error("Invalid bytecode. Wrong exception type", this_method, instr)
                }
                canEscape = false
                
            case .invokestatic:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                methodres := get_methodrefconst_method(vm, this_method.parent.class_file, index)
                if methodres.is_err {
                    return verification_error(methodres.error.(string), this_method, instr)
                }
                method := methodres.value.(^Method)
                if !hasFlag(method.access_flags, MethodAccessFlags.Static) {
                    return verification_error("Invalid bytecode. Expected static method", this_method, instr)
                
                }
                stack_size := len(method.args)
                reversed_args := slice.clone(method.args)
                
                slice.reverse(reversed_args)
                defer delete(reversed_args)
                argi := 0
                for argi < len(reversed_args) {
                    arg := reversed_args[argi]
                    typ := stack_pop(stack)
                    if typ == nil {
                        return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                    }
                    if typ.class != arg && !is_stacktype_subtype_of(typ, arg) && !(type_is_integer(typ.class) && type_is_integer(arg)) {
                        return verification_error("Invalid bytecode. Wrong argument type", this_method, instr)
                    }
                    if typ.class.name == "double" || typ.class.name == "long" {
                        argi += 1
                    }
                    argi += 1
                }
                if method.ret_type != vm.classes["void"] {
                    if !stack_push(stack, method.ret_type) {
                        return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                    }
                }
            case .invokeinterface:
                index := instr.(SimpleInstruction).operand.(classparser.TwoOperands).op1
                interface_method := get_interface_method(vm, this_method.parent.class_file, index)
                if interface_method.is_err {
                    return verification_error(interface_method.error.(string), this_method, instr)
                }
                method := interface_method.value.(^Method)
                stack_size := len(method.args)
                reversed_args := slice.clone(method.args)
                slice.reverse(reversed_args)
                defer delete(reversed_args)
                argi := 0
                for argi < len(reversed_args) {
                    arg := reversed_args[argi]
                    typ := stack_pop(stack)
                    if typ == nil {
                        return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                    }
                    if typ.class != arg && !is_stacktype_subtype_of(typ, arg) && !(type_is_integer(typ.class) && type_is_integer(arg)) {
                        return verification_error("Invalid bytecode. Wrong argument type", this_method, instr)
                    }
                    if typ.class.name == "double" || typ.class.name == "long" {
                        argi += 1
                    }
                    argi += 1
                }
                if !hasFlag(method.access_flags, MethodAccessFlags.Static) {
                    this := stack_pop(stack) 
                    if this == nil {
                        return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                    }
                    if this.class != method.parent && !does_implements_interface(this.class, method.parent) {
                        return verification_error("Invalid bytecode. Wrong argument type", this_method, instr)
                    }
                }
                if method.ret_type != vm.classes["void"] {
                    if !stack_push(stack, method.ret_type) {
                        return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                    }
                }
            
            
            case .invokespecial, .invokevirtual:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                methodres := get_methodrefconst_method(vm, this_method.parent.class_file, index)
                if methodres.is_err {
                    return verification_error(methodres.error.(string), this_method, instr)
                }
                method := methodres.value.(^Method)
                stack_size := len(method.args)
                reversed_args := slice.clone(method.args)
                slice.reverse(reversed_args)
                defer delete(reversed_args)
                argi := 0
                for argi < len(reversed_args) {
                    arg := reversed_args[argi]
                    typ := stack_pop(stack)
                    if typ == nil {
                        return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                    }
                    if typ.class != arg && !is_stacktype_subtype_of(typ, arg) && !(type_is_integer(typ.class) && type_is_integer(arg)) {
                        return verification_error("Invalid bytecode. Wrong argument type", this_method, instr)
                    }
                    if typ.class.name == "double" || typ.class.name == "long" {
                        argi += 1
                    }
                    argi += 1
                }
                if !hasFlag(method.access_flags, MethodAccessFlags.Static) {
                    this := stack_pop(stack) 
                    if this == nil {
                        return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                    }
                    if this.class != method.parent && !is_stacktype_subtype_of(this, method.parent) {
                        return verification_error("Invalid bytecode. Wrong argument type", this_method, instr)
                    }
                }
                if method.ret_type != vm.classes["void"] {
                    if !stack_push(stack, method.ret_type) {
                        return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                    }
                }
            case .lconst_0, .lconst_1:
                if !stack_push(stack, vm.classes["int"]) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }
            case .iconst_0, .iconst_1, .iconst_2, .iconst_3, .iconst_4, .iconst_5, .iconst_m1:
                if !stack_push(stack, vm.classes["int"]) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }
            case .iinc:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.TwoOperands).op1
                t := locals[index] == nil ? vm.classes["int"] : locals[index]
                if !type_is_integer(t) {
                    return verification_error("Invalid bytecode. Expected integer value", this_method, instr)
                }
            case .if_icmpeq, .if_icmpge, .if_icmpgt, .if_icmple, .if_icmplt, .if_icmpne:
                if stack.count < 2 {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                value2 := stack_pop_class(stack)
                value1 := stack_pop_class(stack)
                if !type_is_integer(value2) || !type_is_integer(value1) {
                    return verification_error("Invalid bytecode. Expected integer value", this_method, instr)
                }
                next_block := find_codeblock_by_start(cblocks, instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op)
                if next_block == nil {
                    return verification_error("Invalid bytecode. Invalid jump offset", this_method, instr)
                }
                if next_block.stack_at_start == nil {
                    next_block.stack_at_start = new_clone(copy_stack(stack^))
                    next_block.locals = slice.clone(locals) 
                    res := calculate_stack(vm, next_block, cblocks, this_method)
                    if res != nil {
                        return res
                    }
                }
                else if !stack_eq(next_block.stack_at_start, stack) || !locals_equal(locals, next_block.locals)  {
                    return verification_error("Invalid bytecode. Inconsistent stack", this_method, instr)
                }
            case .if_acmpne, .if_acmpeq:
                if stack.count < 2 {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                value2 := stack_pop(stack)
                value1 := stack_pop(stack)
                if !is_reference_type(vm, value2.class) || !is_reference_type(vm, value1.class) {
                    return verification_error("Invalid bytecode. Expected reference-type value", this_method, instr)
                }
                next_block := find_codeblock_by_start(cblocks, instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op)
                if next_block == nil {
                    return verification_error("Invalid bytecode. Invalid jump offset", this_method, instr)
                }
                if next_block.stack_at_start == nil {
                    next_block.stack_at_start = new_clone(copy_stack(stack^))
                    next_block.locals = slice.clone(locals) 
                    res := calculate_stack(vm, next_block, cblocks, this_method)
                    if res != nil {
                        return res
                    }
                }
                else if !stack_eq(next_block.stack_at_start, stack) || !locals_equal(locals, next_block.locals)  {
                    return verification_error("Invalid bytecode. Inconsistent stack", this_method, instr)
                }
            case .dup_x1:
                if stack.count < 2 {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                t1 := stack_pop(stack)
                t2 := stack_pop(stack)
                if !stack_push(stack, t1.class, t1.is_null) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }
                if !stack_push(stack, t2.class, t2.is_null) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }
                if !stack_push(stack, t1.class, t1.is_null) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }

            case .dup:
                if stack.count == 0 {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                t := stack_pop(stack)
                if !stack_push(stack, t.class, t.is_null) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }
                if !stack_push(stack, t.class, t.is_null) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }

            case .aaload:
                index := stack_pop_class(stack)
                if index == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if !type_is_integer(index) {
                    return verification_error("Invalid bytecode. Expected integer on stack", this_method, instr)
                }
                arr := stack_pop(stack)
                if arr == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if !is_stacktype_array_of(arr, vm.object) {
                    return verification_error("Invalid bytecode. Expected array of objects", this_method, instr)
                }
                stack_push(stack, arr.class.underlaying)
            case .iaload:
                index := stack_pop_class(stack)
                if index == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if !type_is_integer(index) {
                    return verification_error("Invalid bytecode. Expected integer on stack", this_method, instr)
                }
                arr := stack_pop(stack)
                if arr == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if !is_stacktype_array_of(arr, vm.classes["int"]) {
                    return verification_error("Invalid bytecode. Expected array of chars", this_method, instr)
                }
                if !stack_push(stack, vm.classes["int"]) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }
            case .baload:
                index := stack_pop_class(stack)
                if index == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if !type_is_integer(index) {
                    return verification_error("Invalid bytecode. Expected integer on stack", this_method, instr)
                }
                arr := stack_pop(stack)
                if arr == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if !is_stacktype_array_of(arr, vm.classes["byte"]) {
                    return verification_error("Invalid bytecode. Expected array of bytes", this_method, instr)
                }
                if !stack_push(stack, vm.classes["byte"]) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }
            case .caload:
                index := stack_pop_class(stack)
                if index == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if !type_is_integer(index) {
                    return verification_error("Invalid bytecode. Expected integer on stack", this_method, instr)
                }
                arr := stack_pop(stack)
                if arr == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if !is_stacktype_array_of(arr, vm.classes["char"]) {
                    return verification_error("Invalid bytecode. Expected array of chars", this_method, instr)
                }
                if !stack_push(stack, vm.classes["char"]) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }
            case .ifnull, .ifnonnull:
                typ := stack_pop_class(stack)
                if !is_reference_type(vm, typ) {
                    return verification_error("Invalid bytecode. Expected reference type on stack", this_method, instr)
                }
                next_block := find_codeblock_by_start(cblocks, instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op)
                if next_block == nil {
                    return verification_error("Invalid bytecode. Invalid jump offset", this_method, instr)
                }
                if next_block.stack_at_start == nil {
                    next_block.stack_at_start = new_clone(copy_stack(stack^))
                    next_block.locals = slice.clone(locals) 
                    res := calculate_stack(vm, next_block, cblocks, this_method)
                    if res != nil {
                        return res
                    }
                }
                else if !stack_eq(next_block.stack_at_start, stack) || !locals_equal(locals, next_block.locals)  {
                    return verification_error("Invalid bytecode. Inconsistent stack", this_method, instr)
                }
            case .ifeq, .ifge, .ifgt, .ifle, .iflt, .ifne:
                typ := stack_pop_class(stack)
                if !type_is_integer(typ) {
                    return verification_error("Invalid bytecode. Expected integer on stack", this_method, instr)
                }
                next_block := find_codeblock_by_start(cblocks, instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op)
                if next_block == nil {
                    return verification_error("Invalid bytecode. Invalid jump offset", this_method, instr)
                }
                if next_block.stack_at_start == nil {
                    next_block.stack_at_start = new_clone(copy_stack(stack^))
                    next_block.locals = slice.clone(locals) 
                    res := calculate_stack(vm, next_block, cblocks, this_method)
                    if res != nil {
                        return res
                    }
                }
                else if !stack_eq(next_block.stack_at_start, stack) || !locals_equal(locals, next_block.locals)  {
                    return verification_error("Invalid bytecode. Inconsistent stack", this_method, instr)
                }
            case .goto, .goto_w:
                next_block := find_codeblock_by_start(cblocks, instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op)
                if next_block == nil {
                    return verification_error("Invalid bytecode. Invalid jump offset", this_method, instr)
                }
                if next_block.stack_at_start == nil {
                    next_block.stack_at_start = new_clone(copy_stack(stack^))
                    next_block.locals = slice.clone(locals) 
                    res := calculate_stack(vm, next_block, cblocks, this_method)
                    if res != nil {
                        return res
                    }
                }
                else if !stack_eq(next_block.stack_at_start, stack) || !locals_equal(locals, next_block.locals)  {
                    for local, i in locals {
                        fmt.println(local.name, next_block.locals[i].name)
                    }                   
                    panic("")
//                     return verification_error("Invalid bytecode. Inconsistent stack", this_method, instr)
                }
                canEscape = false
            case .multianewarray:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.TwoOperands).op1   
                dimensions := instr.(classparser.SimpleInstruction).operand.(classparser.TwoOperands).op2
                
                if stack.count < dimensions {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                for i in 0..<dimensions {
                    indextyp := stack_pop_class(stack)
                    if !type_is_integer(indextyp) {
                        return verification_error("Invalid bytecode. Index must be integer", this_method, instr)
                    }
                }
                cl := get_class(vm, this_method.parent.class_file, index)
                if cl.is_err {
                    return verification_error(cl.error.(string), this_method, instr)
                }
                stack_push(stack, cl.value.(^Class))
            case .aload_0, .aload_1, .aload_2, .aload_3,
            .iload_0, .iload_1, .iload_2, .iload_3,
            .lload_0, .lload_1, .lload_2, .lload_3,
            .fload_0, .fload_1, .fload_2, .fload_3,
            .dload_0, .dload_1, .dload_2, .dload_3,
            .astore_0, .astore_1, .astore_2, .astore_3,
            .istore_0, .istore_1, .istore_2, .istore_3,
            .lstore_0, .lstore_1, .lstore_2, .lstore_3,
            .fstore_0, .fstore_1, .fstore_2, .fstore_3,
            .dstore_0, .dstore_1, .dstore_2, .dstore_3:
                panic("should not happen")
            case .dconst_0, .dconst_1:
                if !stack_push(stack, vm.classes["double"]) {
                    return verification_error("Invalid bytecode. Exceeded max_stack", this_method, instr)
                }
            
            case .l2i:
                t := stack_pop_class(stack)
                if t == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if t != vm.classes["long"] {
                    return verification_error("Invalid bytecode. Expected long value", this_method, instr)
                }
                stack_push(stack, vm.classes["int"])
            case .d2i:
                t := stack_pop_class(stack)
                if t == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if t != vm.classes["double"] {
                    return verification_error("Invalid bytecode. Expected double value", this_method, instr)
                }
                stack_push(stack, vm.classes["int"])
            case .i2s:
                t := stack_pop_class(stack)
                if t == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if !type_is_integer(t) {
                    return verification_error("Invalid bytecode. Expected integer value", this_method, instr)
                }
                stack_push(stack, vm.classes["short"])
            case .i2c:
                t := stack_pop_class(stack)
                if t == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if !type_is_integer(t) {
                    return verification_error("Invalid bytecode. Expected integer value", this_method, instr)
                }
                stack_push(stack, vm.classes["char"])
            case .i2l:
                t := stack_pop_class(stack)
                if t == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if !type_is_integer(t) {
                    return verification_error("Invalid bytecode. Expected integer value", this_method, instr)
                }
                stack_push(stack, vm.classes["long"])
            case .i2d:
                t := stack_pop_class(stack)
                if t == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if !type_is_integer(t) {
                    return verification_error("Invalid bytecode. Expected integer value", this_method, instr)
                }
                stack_push(stack, vm.classes["double"])
            case .dsub, .dadd, .dmul, .ddiv:
                if stack.count < 2 {
                    fmt.println(stack)
                    panic("")
//                     return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                value2 := stack_pop_class(stack)
                value1 := stack_pop_class(stack)
                if value2 != vm.classes["double"] || value1 != vm.classes["double"] {
                    return verification_error("Invalid bytecode. Expected double value", this_method, instr)
                }
                stack_push(stack, value1)
            case .lneg:
                if stack.count < 1 {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                value1 := stack_pop_class(stack)
                if value1.name != "long" {
                    return verification_error("Invalid bytecode. Expected long value", this_method, instr)
                }
                stack_push(stack, value1)
            case .ineg:
                if stack.count < 1 {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                value1 := stack_pop_class(stack)
                if !type_is_integer(value1) {
                    return verification_error("Invalid bytecode. Expected integer value", this_method, instr)
                }
                stack_push(stack, value1)
                
            case .lsub, .ladd, .lmul, .ldiv, .lrem, .lor, .land, .lxor:
                if stack.count < 2 {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                value2 := stack_pop_class(stack)
                value1 := stack_pop_class(stack)
                if value1 != vm.classes["long"] || value1 != vm.classes["long"] {
                    return verification_error("Invalid bytecode. Expected integer value", this_method, instr)
                }
                stack_push(stack, value1)
            case .isub, .iadd, .imul, .idiv, .irem, .ior, .iand, .ixor:
                if stack.count < 2 {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                value2 := stack_pop_class(stack)
                value1 := stack_pop_class(stack)
                if !type_is_integer(value2) || !type_is_integer(value1) {
                    return verification_error("Invalid bytecode. Expected integer value", this_method, instr)
                }
                stack_push(stack, value1)
            case .arraylength:
                array := stack_pop(stack)
                if array == nil {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                if array.class.class_type != ClassType.Array {
                    return verification_error("Invalid bytecode. Expected array", this_method, instr)
                }
                stack_push(stack, vm.classes["int"])
            case .lcmp:
                if stack.count < 2 {
                    return verification_error("Invalid bytecode. Not enough items on stack", this_method, instr)
                }
                t1 := stack_pop_class(stack)
                t2 := stack_pop_class(stack)
                if t1.name != "long" || t2.name != "long" {
                    return verification_error("Invalid bytecode. Expected long", this_method, instr)
                }
                stack_push(stack, vm.classes["int"])
            case:
                fmt.println(instr)
                panic("unimplemented")
        }
    }
    if canEscape {
        next := find_codeblock_by_start(cblocks, cb.end) 
        if next.stack_at_start == nil {
            next.stack_at_start = new_clone(copy_stack(stack^))
            next.locals = slice.clone(locals) 
            return calculate_stack(vm, next, cblocks, this_method)
        }
        else if !stack_eq(next.stack_at_start, stack) || !locals_equal(locals, next.locals)  {
            fmt.println(cb.code[len(cb.code) - 1])
            for local in locals {
                fmt.printf("%s ", local == nil ? "<nil>" : local.name)
            }
            fmt.println()
            for local in next.locals {
                fmt.printf("%s ", local == nil ? "<nil>" : local.name)
            }
            panic("")
//             return verification_error("Invalid bytecode. Inconsistent stack", this_method, {})
        }
    }
    return nil
}
type_is_object :: proc(typ: ^Class) -> bool {
    return typ.class_type == ClassType.Class
} 
get_interface_method :: proc(vm: ^VM, class_file: ^classparser.ClassFile, index: int) -> shared.Result(^Method, string) {
    using shared
    using classparser
    if index <= 0 || index > len(class_file.constant_pool) {
        return Err(^Method, "Invalid bytecode")
    }
    interface, ok := class_file.constant_pool[index - 1].(classparser.InterfaceMethodRefInfo)
    if !ok {
        return Err(^Method, "Invalid bytecode")
    }
    class := get_class(vm, class_file, int(interface.class_index))
    if class.is_err {
        return Err(^Method, class.error.(string))
    }
    classs := class.value.(^Class)
    name_and_type := resolve_name_and_type(class_file, interface.name_and_type_index)
    if name_and_type == nil {
        return Err(^Method, "Invalid bytecode")
    }
    name := resolve_utf8(class_file, name_and_type.(NameAndTypeInfo).name_index)
    descriptor:= resolve_utf8(class_file, name_and_type.(NameAndTypeInfo).descriptor_index)
    if name == nil || descriptor == nil {
        return Err(^Method, "Invalid bytecode")
    }
    method := find_method_by_name_and_descriptor(classs, name.(string), descriptor.(string))
    if method == nil {
        return Err(^Method, "Unknown method")
    }
    return Ok(string, method)
}
get_class :: proc(vm: ^VM, class_file: ^classparser.ClassFile, index: int) -> shared.Result(^Class, string) {
    using shared
    using classparser
    name := resolve_class_name(class_file, cast(u16)index)
    if name == nil {
        
        return Err(^Class, "Invalid bytecode")
    }
    return load_class(vm, name.(string))
}
get_constant_type :: proc(vm: ^VM, class_file: ^classparser.ClassFile, index: int) -> shared.Result(^Class, string) {
    using shared
    using classparser
    if index == 0 || index > len(class_file.constant_pool) {
        return Err(^Class, "Invalid bytecode. Constant index outside of constant_pool bounds")
    }    
    const := class_file.constant_pool[index - 1]
    #partial switch in const {
        case IntegerInfo:
            return Ok(string, vm.classes["int"])
        case LongInfo:
            return Ok(string, vm.classes["long"])
        case FloatInfo:
            return Ok(string, vm.classes["float"])
        case DoubleInfo:
            return Ok(string, vm.classes["double"])
        case StringInfo:
            return Ok(string, vm.classes["java/lang/String"])
        case:
            fmt.println(const)
            panic("unimplemented")
    }
}
find_codeblock_by_start :: proc(blocks: []CodeBlock, start: int) -> ^CodeBlock {
    for &block in blocks {
        if block.start == start  {
            return &block
        }
    }
    return nil
}
find_method_block_indices :: proc(vm: ^VM, method: ^Method)-> []int {
    using classparser
    blocks := make([dynamic]int)
    append(&blocks, 0)
    instructions := method.code.(CodeAttribute).code
    exception_table := method.code.(CodeAttribute).exception_table
    for exception in exception_table {
        append(&blocks, cast(int)exception.handler_pc)
    }
    i := 0
    for i < len(instructions) {
        instr := instructions[i]
        i += 1
        switch in instr {
            case SimpleInstruction:
                sinstr := instr.(classparser.SimpleInstruction)
                #partial switch sinstr.opcode {
                    case .goto, .goto_w, .ifeq, .ifge, .ifgt, .ifle, .iflt, .ifne, .ifnull,
                    .if_acmpeq, .if_acmpne, .if_icmpeq, .if_icmpge, .if_icmpgt, .if_icmple,
                    .if_icmplt, .if_icmpne, .ifnonnull:
                        next := i < len(instructions) ? get_instr_offset(instructions[i]) : sinstr.offset + 1
                        append(&blocks, next)
                        append(&blocks, sinstr.operand.(classparser.OneOperand).op)
                    case ._return, .ireturn, .lreturn, .freturn, .dreturn, .areturn, .athrow:
                        append(&blocks, sinstr.offset + 1)
                        
                }
            case TableSwitch:
                tinstr := instr.(classparser.TableSwitch)
                append(&blocks, tinstr.default)
                append_elems(&blocks, ..tinstr.offsets)
            case LookupSwitch:
                linstr := instr.(classparser.LookupSwitch)
                append(&blocks, linstr.default)
                for pair in linstr.pairs {
                    append(&blocks, pair.snd)
                }
        }
    }
    slice.sort(blocks[:]) 
    result := make([]int, len(blocks))
    bi := 0
    ri := 0
    // remove duplicates
    for bi < len(blocks) {
        result[ri] = blocks[bi]
        ri += 1
        for bi < len(blocks) && blocks[bi] == result[ri - 1] {
            bi += 1 
        }
    }
    delete(blocks)
    return result[:ri]
}

