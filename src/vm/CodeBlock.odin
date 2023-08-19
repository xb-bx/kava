package vm
import "kava:classparser"
import "kava:shared"
import "core:slice"
import "core:fmt"

CodeBlock :: struct {
    start: int,
    end: int,
    stack_at_start: ^TypeStack,
    code: []classparser.Instruction,
    visited: bool,
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
    if endi < starti {
        endi = starti
    }
    if inclusive_end {

        return instructions[starti:endi + 1]
    }
    else {
        return instructions[starti:endi]
    }
}
split_method_into_codeblocks :: proc(vm: ^VM, method: ^Method) -> []CodeBlock {
    using classparser
    assert(method.code != nil)
    blocks := find_method_block_indices(vm, method)
    codeattr := method.code.(CodeAttribute)
    instructions := codeattr.code
    res := make([]CodeBlock, len(blocks) - 1) 
    blocki := 0
    for blocki < len(blocks) - 1 {
        start := blocks[blocki]
        instrs :=  split_instructions_by_byteoffset(instructions, start, blocks[blocki + 1], blocki + 1 == len(blocks) - 1)
        if start != 0 && start != get_instr_offset(instructions[len(instructions) - 1]){
            instrs = instrs[1:]
        }
        res[blocki] = CodeBlock {
            start = start,
            end = blocks[blocki + 1],
            stack_at_start = nil,
            code = instrs,
            visited = false,
        }
        blocki += 1
    }
    res[0].stack_at_start = new_clone(make_stack(cast(int)codeattr.max_stack))
    method.locals = make([]^Class, cast(int)codeattr.max_locals)
    if !hasFlag(method.access_flags, MemberAccessFlags.Static) {
        method.locals[0] = method.parent
        for arg, i in method.args {
            method.locals[i + 1] = arg
        }
    }
    else {
        for arg, i in method.args {
            method.locals[i] = arg
        }
    }
    err := calculate_stack(vm, &res[0], res, method) 
    if err != nil {
        panic(err.(string))
    }
    return res
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
is_subtype_of :: proc(subtype: ^Class, parent: ^Class) -> bool {
    if subtype.super_class == parent {
        return true
    }
    else if subtype.super_class != nil {
        return is_subtype_of(subtype.super_class, parent)
    }
    return false
}
is_array_of :: proc(array_class: ^Class, elem_class: ^Class) -> bool {
    return array_class.class_type == ClassType.Array && (array_class.underlaying == elem_class || is_subtype_of(elem_class, array_class.underlaying))
}
calculate_stack :: proc(vm: ^VM, cb: ^CodeBlock, cblocks: []CodeBlock, method: ^Method) -> Maybe(string) {
    using classparser
    if cb.visited == true {
        return nil
    }
    cb.visited = true
    stack := new_clone(copy_stack(cb.stack_at_start^))
    i := 0
    canEscape := true
    for i < len(cb.code) {
        instr := cb.code[i]
        i += 1
        #partial switch get_instr_opcode(instr) {
            case .getstatic:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                type := get_fieldrefconst_type(vm, method.parent.class_file, index)
                if type.is_err {
                    return type.error
                }
                if !stack_push(stack, type.value.(^Class)) { panic("") }
                
            case .istore:
                t := stack_pop(stack)
                if t == nil || !type_is_integer(t) {
                    return "Invalid bytecode. Expected integer on stack before istore operation"
                }
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                if method.locals[index] == nil {
                    method.locals[index] = t
                }
            case .iload:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                if index >= len(method.locals) || !type_is_integer(method.locals[index]) {
                    return "Invalid bytecode. Expected integer local variable"
                }
                stack_push(stack, method.locals[index])
            case .tableswitch:
                canEscape = false
                t := stack_pop(stack) 
                if t == nil || !type_is_integer(t) {
                    return "Invalid bytecode. Expected integer on stack before istore operation"
                }
                table := instr.(classparser.TableSwitch)
                for offset in table.offsets {
                    block := find_codeblock_by_start(cblocks, offset)         
                    if block == nil {
                        fmt.println(cblocks, offset)
                        return "Invalid bytecode. Invalid jump offset"
                    }
                    if block.stack_at_start == nil {
                        block.stack_at_start = new_clone(copy_stack(stack^))
                        calculate_stack(vm, block, cblocks, method)
                    }
                    else if !stack_eq(block.stack_at_start, stack) {
                        return "Invalid bytecode. Inconsistent stack"
                    }
                }
                default_block := find_codeblock_by_start(cblocks, table.default)
                if default_block == nil {
                    return "Invalid bytecode. Invalid jump offset"
                }
                if default_block.stack_at_start == nil {
                    default_block.stack_at_start = new_clone(copy_stack(stack^))
                    calculate_stack(vm, default_block, cblocks, method)
                }
                else if !stack_eq(default_block.stack_at_start, stack) {
                    fmt.println(stack, default_block.stack_at_start)
                    return "Invalid bytecode. Inconsistent stack"
                }
            case .ldc:
                index := instr.(classparser.SimpleInstruction).operand.(classparser.OneOperand).op   
                typ := get_constant_type(vm, method.parent.class_file, index)
                if typ.is_err {
                    return typ.error
                }
                if !stack_push(stack, typ.value.(^Class)) {
                    return "Invalid bytecode. Exceeded max_stack"
                }

            case .aastore:
                if stack.count < 3 {
                    return "Invalid bytecode. Not enough items on stack" 
                }
                value := stack_pop(stack)
                index := stack_pop(stack)
                array := stack_pop(stack)
                if !is_subtype_of(value, vm.object) {
                    return "Invalid bytecode. value must be reference type" 
                }
                if !type_is_integer(index) {
                    return "Invalid bytecode. Index must be integer" 
                }
                if !is_array_of(array, value) {
                    return "Invalid bytecode. Index must be integer" 
                }
            case ._return:
                if method.ret_type != vm.classes["void"] {
                    return "Invalid bytecode. Cannot return void from method"
                }
                canEscape = false

            
            
            
            case:
                fmt.println(instr)
                panic("unimplemented")
        }
    }
    if canEscape {
        next := find_codeblock_by_start(cblocks, cb.end) 
        if next.stack_at_start == nil {
            return calculate_stack(vm, next, cblocks, method)
        }
        else {
            if !stack_eq(stack, next.stack_at_start) {
                return "Invalid bytecode. Inconsistent stack"
            }
        }
    }
    return nil
}
type_is_object :: proc(typ: ^Class) -> bool {
    return typ.class_type == ClassType.Class
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
                    case ._return, .ireturn, .lreturn, .freturn, .dreturn, .areturn:
                        append(&blocks, sinstr.offset + 1)
                        
                }
            case TableSwitch:
                tinstr := instr.(classparser.TableSwitch)
//                 append(&blocks, tinstr.offset)
                append(&blocks, tinstr.default)
                append_elems(&blocks, ..tinstr.offsets)
            case LookupSwitch:
                linstr := instr.(classparser.LookupSwitch)
//                 append(&blocks, linstr.offset)
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

