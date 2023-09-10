package vm
import "kava:shared"
import "kava:classparser"
import "zip:zip"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:path/filepath"
import "core:slice"
import "core:intrinsics"
import "core:runtime"
import "core:sys/windows"
import "x86asm:x86asm"

VM :: struct {
    classpaths: []string,
    classes: map[string]^Class,
    object: ^Class,
    ctx: runtime.Context,
    gc: ^GC,
}
array_type_primitives := [?]PrimitiveType { PrimitiveType.Boolean, PrimitiveType.Char, PrimitiveType.Float, PrimitiveType.Double, PrimitiveType.Byte, PrimitiveType.Short, PrimitiveType.Int, PrimitiveType.Long }
primitive_names: map[PrimitiveType]string = {
    PrimitiveType.Int = "int",
    PrimitiveType.Char = "char",
    PrimitiveType.Byte = "byte",
    PrimitiveType.Short = "short",
    PrimitiveType.Float = "float",
    PrimitiveType.Double = "double",
    PrimitiveType.Long = "long",
    PrimitiveType.Void = "void",
    PrimitiveType.Boolean = "boolean",
}
primitive_descriptors : map[PrimitiveType]string = {
    PrimitiveType.Int = "I",
    PrimitiveType.Char = "C",
    PrimitiveType.Byte = "B",
    PrimitiveType.Short = "S",
    PrimitiveType.Float = "F",
    PrimitiveType.Double = "D",
    PrimitiveType.Long = "J",
    PrimitiveType.Void = "V",
    PrimitiveType.Boolean = "Z",
}
primitive_sizes : map[PrimitiveType]int = {
    PrimitiveType.Int = 4,
    PrimitiveType.Char = 2,
    PrimitiveType.Byte = 1,
    PrimitiveType.Short = 2,
    PrimitiveType.Float = 4,
    PrimitiveType.Double = 8,
    PrimitiveType.Long = 8,
    PrimitiveType.Void = 0,
    PrimitiveType.Boolean = 1,
}
hasFlag :: proc(flags: $T, flag: T) -> bool 
    where intrinsics.type_is_enum(T) {
    return cast(int)flags & cast(int)flag > 0
}
make_array_type :: proc(vm: ^VM, type: ^Class) -> ^Class {
    parts := [?]string {"[", type.name}
    if type.class_type == ClassType.Primitive {
        parts[1] = primitive_descriptors[type.primitive]  
    }
    name := strings.concatenate(parts[:])
    if class, found := vm.classes[name]; found {
        delete(name)
        return class
    }
    typ := new(Class) 
    typ.name = name
    typ.class_type = ClassType.Array
    typ.underlaying = type
    typ.super_class = vm.classes["java/lang/Object"]
    typ.size = size_of(ArrayHeader)
    vm.classes[name] = typ 
    
    return typ
} 
make_primitive :: proc(vm: ^VM, primitive: PrimitiveType, name: string, size: int) -> ^Class {
    if class, found := vm.classes[name]; found {
        return class
    }
    type := new(Class)
    type.class_type = ClassType.Primitive
    type.name = name
    type.primitive = primitive
    type.size = size
    vm.classes[name] = type
    return type
}
uncompress_if_exists :: proc(zip_file_name: string, file_name: string) -> []u8 {
    zip_file := zip.open(zip_file_name, 0, zip.OpenMode.Read)
    defer if zip_file != nil { zip.close(zip_file) }
    if zip_file == nil {
        return nil
    }
    err := zip.entry_open(zip_file, file_name)
    if err != .ENONE {
        return nil
    }
    bytes:[]u8 = nil
    bytes, err = zip.entry_read(zip_file)
    if err != .ENONE {
        return nil
    }
    return bytes
}
find_method_by_name_and_descriptor :: proc(class: ^Class, name: string, descriptor: string) -> ^Method {
    for &method in class.methods {
        if method.name == name && method.descriptor == descriptor {
            return &method
        }
    }
    return nil
}
replace_body :: proc(method: ^Method, procptr: rawptr) {
    using x86asm
    assembler := Assembler {}
    init_asm(&assembler)
    defer delete_asm(&assembler)
    mov(&assembler, Reg64.Rax, transmute(int)procptr)
    jmp(&assembler, Reg64.Rax)
    method.jitted_body = alloc_executable(len(assembler.bytes))
    for b, i in assembler.bytes {
        method.jitted_body[i] = b
    }
}
load_class :: proc(vm: ^VM, class_name: string) -> shared.Result(^Class, string) {
    using classparser
    using shared 
    if cl, is_found := vm.classes[class_name]; is_found {
        return Ok(string, cl)
    } 
    else if class_name[0] == '[' || len(class_name) == 1 || strings.contains(class_name, ";") {
        type, _ := type_descriptor_to_type(vm, class_name)
        return type
    }
    if len(vm.classpaths) != 0 {
        for path in vm.classpaths {
            arr := [2]string{class_name, ".class"}
            class_file := strings.concatenate(arr[:])
            defer delete(class_file)
            classpath := [2]string{path, class_file}
            fullpath := filepath.join(classpath[:])
            defer delete(fullpath)
            classfile: ^ClassFile = nil
            if filepath.ext(path) == ".jar" {
                bytes := uncompress_if_exists(path, class_file) 
                defer delete(bytes)
                if bytes == nil {
                    continue
                }
                res := classparser.read_class_file(bytes)
                if res.is_err {
                    return Err(^Class, res.error.(string))
                }
                classfile = new_clone(res.value.(ClassFile))

            }
            else {
                if os.exists(fullpath) {
                    bytes, _ := os.read_entire_file(fullpath)
                    defer delete(bytes)
                    res := read_class_file(bytes)
                    if res.is_err {
                        return Err(^Class, res.error.(string))
                    }
                    classfile = new_clone(res.value.(ClassFile))
                }
                else {
                    continue
                }
            }
            classname := resolve_class_name(classfile, classfile.this_class)
            if classname == nil || classname.(string) != class_name {
                return Err(^Class, fmt.aprintf("Could not find class %s", class_name))
            }
            class := new(Class)
            class.class_file = classfile
            if class_name == "java/lang/Object" {
                vm.object = class
            }
            vm.classes[class_name] = class
            name := resolve_class_name(classfile, classfile.this_class)
            if name == nil {
                delete_class(classfile^)
                free(classfile)
                return Err(^Class, fmt.aprintf("Invalid class file %s", class_name))
            }
            super_class_name := resolve_class_name(classfile, classfile.super_class)
            if super_class_name == nil && class_name != "java/lang/Object" {
                delete_class(classfile^)
                free(classfile)
                return Err(^Class, fmt.aprintf("Invalid class file %s", class_name))
            }
            if super_class_name != nil {
                super_class := load_class(vm, super_class_name.(string))
                if super_class.is_err {
                    return super_class
                }
                class.super_class =  super_class.value.(^Class)
            }
            class.name = name.(string)
            class.interfaces = make([]^Class, len(classfile.interfaces))
            for interface,i in classfile.interfaces {
                ifacename := resolve_class_name(classfile, interface) 
                if ifacename == nil {
                    delete_class(classfile^)
                    free(classfile)
                    return Err(^Class, fmt.aprintf("Invalid class file %s", classfile))
                }
                interfac := load_class(vm, ifacename.(string))
                if interfac.is_err {
                    return interfac
                }
                class.interfaces[i] = interfac.value.(^Class)


            }
            class.fields = make([]Field, len(classfile.fields))
            instance_fields := make([dynamic]^Field) 
            for field,i in classfile.fields {
                fld := Field {}
                name := resolve_utf8(classfile, field.name_index)
                if name == nil {
                    panic("")
                }
                fld.access_flags = field.access_flags
                typ := resolve_utf8(classfile, field.descriptor_index)
                if typ == nil {
                    panic("")
                }
                fld.name = name.(string)
                t, _ := type_descriptor_to_type(vm, typ.(string))
                if t.is_err {
                    return t
                }
                fld.type = t.value.(^Class)
                class.fields[i] = fld
                if !hasFlag(fld.access_flags, MemberAccessFlags.Static) {
                    append(&instance_fields, &class.fields[i]) 
                }

            }
            class.instance_fields = instance_fields[:]
            calculate_class_size(class)
            class.methods = make([]Method, len(classfile.methods)) 
            for method,i in classfile.methods {
                meth := Method {}
                name := resolve_utf8(classfile, method.name_index)
                if name == nil {
                    panic("")
                }
                typ := resolve_utf8(classfile, method.descriptor_index)
                if typ == nil {
                    panic("")
                }
                meth.name = name.(string)
                meth.descriptor = typ.(string)
                meth.access_flags = method.access_flags
                meth.code = method.bytecode
                err := parse_method_descriptor(vm, &meth, typ.(string))
                if err != nil {
                    return Err(^Class, err.(string))
                }
                meth.parent = class
                class.methods[i] = meth

                
            }
            for const in classfile.constant_pool {
                if classconst, isclass := const.(classparser.ClassInfo); isclass {
                    name := resolve_utf8(classfile, classconst.name_index)
                    if name == nil {
                        return Err(^Class, fmt.aprintf("Invalid class file %s", classfile))
                    }
                    res := load_class(vm, name.(string))
                    if res.is_err {
                        return res
                    }
                }
            }
            return Ok(string, class) 
        }
    }
    return Err(^Class, fmt.aprintf("Could not find class %s", class_name))
}
parse_method_descriptor :: proc(vm: ^VM, method: ^Method, descriptor: string) -> Maybe(string) {
    if len(descriptor) < 2 {
        return fmt.aprintf("Invalid descriptor %s of method %s", descriptor, method.name)
    }
    if descriptor[0] != '(' {
        return fmt.aprintf("Invalid descriptor %s of method %s", descriptor, method.name)
    }
    types := make([dynamic]^Class)
    i := 1
    for descriptor[i] != ')' {
        type, read := type_descriptor_to_type(vm, descriptor[i:])
        if type.is_err {
            return type.error.(string)
        }
        if type.value.(^Class).primitive == PrimitiveType.Double || type.value.(^Class).primitive == PrimitiveType.Long {
            append(&types, type.value.(^Class))
        }
        append(&types, type.value.(^Class))
        i += read
    }
    i += 1
    retType, read := type_descriptor_to_type(vm, descriptor[i:])
    if retType.is_err {
        return retType.error.(string)
    }
    method.ret_type = retType.value.(^Class)
    method.args = types[:]
    return nil
}
type_descriptor_to_type :: proc(vm: ^VM, descriptor: string) -> (shared.Result(^Class, string), int) {
    using shared
    if len(descriptor) == 0 {
        return Err(^Class, "Empty descriptor"), 0
    }
    switch descriptor[0] {
        case '[':
            i := 0
            for descriptor[i] == '[' {
                i += 1
            }
            type, read := type_descriptor_to_type(vm, descriptor[i:])    
            if type.is_err {
                return type, 0
            }
            restype := type.value.(^Class)
            for j in 0..<i {
                restype = make_array_type(vm, restype)
            }
            return Ok(string, restype), read + i
        case 'I': 
            return Ok(string, vm.classes[primitive_names[PrimitiveType.Int]]), 1
        case 'C': 
            return Ok(string, vm.classes[primitive_names[PrimitiveType.Char]]), 1
        case 'D': 
            return Ok(string, vm.classes[primitive_names[PrimitiveType.Double]]), 1
        case 'J': 
            return Ok(string, vm.classes[primitive_names[PrimitiveType.Long]]), 1
        case 'V': 
            return Ok(string, vm.classes[primitive_names[PrimitiveType.Void]]), 1
        case 'F': 
            return Ok(string, vm.classes[primitive_names[PrimitiveType.Float]]), 1
        case 'B': 
            return Ok(string, vm.classes[primitive_names[PrimitiveType.Byte]]), 1
        case 'Z': 
            return Ok(string, vm.classes[primitive_names[PrimitiveType.Boolean]]), 1
        case 'S': 
            return Ok(string, vm.classes[primitive_names[PrimitiveType.Short]]), 1
        case 'L':
            index := strings.index_any(descriptor[1:], ";)")
            descrstr := descriptor[1:]
            read := len(descriptor)
            if index != -1 {
                descrstr = descriptor[1:index + 1]
                read = index + 2
            }
            res := load_class(vm, descrstr)
            if res.is_err {
                return res, 0
            }  else {
                return Ok(string, res.value.(^Class)), read
            }
    }
    panic("Should not happen")
}
calculate_class_size :: proc(class: ^Class) {
    size := 0 
    startoffset: i32 = size_of(ObjectHeader)
    if class.super_class != nil && class.super_class.instance_fields != nil && len(class.super_class.instance_fields) > 0 {
        if class.super_class.size == 0 {
            calculate_class_size(class.super_class)
        }
        startoffset = class.super_class.instance_fields[len(class.super_class.instance_fields) - 1].offset + size_of(rawptr)
    }
    if class.instance_fields != nil {
        for field in class.instance_fields {
            assert(field != nil)
            size += size_of(rawptr)
            field.offset = startoffset
            startoffset += size_of(rawptr)
        }
    }
    if class.super_class != nil {
        if class.size == 0 {
            calculate_class_size(class.super_class)
        }
        size += class.super_class.size_without_header
    }
    class.size = size + size_of(ObjectHeader)
    class.size_without_header = size
}



print_constant :: proc(classfile: ^classparser.ClassFile, index:int, file: os.Handle, opcode: classparser.Opcode ) {
    using classparser
    if index > 0 && index <= len(classfile.constant_pool) && need_to_print_const(opcode) {
        const := classfile.constant_pool[index - 1]
        #partial switch in const {
            case ClassInfo:
                name := resolve_class_name(classfile, cast(u16)index)
                fmt.fprint(file, name)
            case IntegerInfo:
                i := const.(IntegerInfo).value
                fmt.fprint(file, "int", i)
            case LongInfo:
                i := const.(LongInfo).value
                fmt.fprint(file, "int", i)
            case MethodRefInfo:
                mref := const.(MethodRefInfo)
                class_name := resolve_class_name(classfile, mref.class_index)
                name_and_type := resolve_name_and_type(classfile, mref.name_and_type_index).(NameAndTypeInfo)
                name := resolve_utf8(classfile, name_and_type.name_index)
                type := resolve_utf8(classfile, name_and_type.descriptor_index)
                fmt.fprintf(file, "%s.%s:%s", class_name, name, type)
            case FieldRefInfo:
                fref := const.(classparser.FieldRefInfo) 
                class_name := resolve_class_name(classfile, fref.class_index)
                name_and_type := resolve_name_and_type(classfile, fref.name_and_type_index).(NameAndTypeInfo)
                name := resolve_utf8(classfile, name_and_type.name_index)
                type := resolve_utf8(classfile, name_and_type.descriptor_index)
                fmt.fprintf(file, "%s.%s:%s", class_name, name, type)
            case StringInfo:
                str := const.(classparser.StringInfo)
                s := resolve_utf8(classfile, str.string_index)
                fmt.fprint(file, s)
            case UTF8Info:
                fmt.fprintf(file, "srcfile")
            case DoubleInfo:
                fmt.fprintf(file, "double %d", const.(classparser.DoubleInfo).value)
            case InterfaceMethodRefInfo:
                mref := const.(InterfaceMethodRefInfo)
                class_name := resolve_class_name(classfile, mref.class_index)
                name_and_type := resolve_name_and_type(classfile, mref.name_and_type_index).(NameAndTypeInfo)
                name := resolve_utf8(classfile, name_and_type.name_index)
                type := resolve_utf8(classfile, name_and_type.descriptor_index)
                fmt.fprintf(file, "interface method %s.%s:%s", class_name, name, type)
            case:
                fmt.println(const)
                panic("unimplemented")

        }
    }
    else {
        fmt.fprint(file, index)
    }
}
need_to_print_const :: proc(opcode: classparser.Opcode) -> bool {
    #partial switch opcode {
        case .aload, .iload, .lload, .fload, .dload, .astore, .istore, .lstore, .dstore, .fstore,
            .ifge, .ifle, .ifeq, .ifgt, .iflt, .ifne, .ifnull,
            .if_acmpeq, .if_acmpne, .if_icmpeq, .if_icmpge, .if_icmpgt, .if_icmple, .if_icmplt, .if_icmpne,
            .bipush, .sipush, .iinc, .aaload, .aastore, .aconst_null, .goto, .goto_w,
            ._return, .areturn, .ireturn, .lreturn, .freturn, .dreturn, .ifnonnull:
            return false
        case .invokespecial, .invokestatic, .invokeinterface, .new, .putfield, .putstatic, .newarray, .getfield, .getstatic, .invokevirtual, .ldc, .ldc_w, .ldc2_w, .instanceof,
            .multianewarray, .checkcast, .anewarray:
            return true 
        case:
            fmt.println(opcode)
            panic("unimplemented")
    }
    return false
}
print_instruction_with_const :: proc(instr: classparser.Instruction, file: os.Handle, class_file: ^classparser.ClassFile, tab: string = "\t") -> int {
    using classparser
    switch in instr {
        case SimpleInstruction: {
            opcode := instr.(SimpleInstruction).opcode
            fmt.fprintf(file, "%s%3i: %s ",tab, instr.(SimpleInstruction).offset, opcode) 
            switch in instr.(SimpleInstruction).operand {
                case OneOperand: {
                    print_constant(class_file, instr.(SimpleInstruction).operand.(OneOperand).op, file, opcode)
                    fmt.fprintln(file)
                }
                case TwoOperands: {
                    ops := instr.(SimpleInstruction).operand.(TwoOperands)
                    print_constant(class_file, ops.op1, file, opcode)
                    fmt.fprint(file, " ")
                    fmt.fprintln(file, ops.op2)
                }
                case nil:
                    fmt.fprintln(file)
            }
            return 1
        } 
        case TableSwitch:
            table := instr.(TableSwitch)
            fmt.fprintf(file, "%s%3i: %s low: %i high: %i\n", tab, table.offset, table.opcode, table.low, table.high) 
            lines := 2
            for off, i in table.offsets {
                lines += 1
                fmt.fprintf(file, "%s\t%7i: %i\n", tab, i + table.low, off) 
            }
            fmt.fprintf(file, "%s\tdefault: %i\n",tab, table.default) 
            return lines
        case LookupSwitch:
            table := instr.(LookupSwitch)
            lines := 2
            fmt.fprintf(file, "%s%3i: %s npairs = %i\n", tab, table.offset, table.opcode, len(table.pairs)) 
            for pair in table.pairs {
                lines += 1
                fmt.fprintf(file, "%s\t%7i: %i\n", tab, pair.fst, pair.snd) 
            }
            fmt.fprintf(file, "%s\tdefault: %i\n", tab, table.default) 
            return lines


    }
    return 0
}


