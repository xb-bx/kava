#+feature dynamic-literals
package vm
import "kava:shared"
import "kava:classparser"
import "zip:zip"
import "core:fmt"
import "core:os"
import "core:time"
import "core:strings"
import "core:path/filepath"
import "core:slice"
import "base:intrinsics"
import "base:runtime"
import "core:sys/windows"
import "x86asm:x86asm"
import "core:unicode/utf16"
import "core:dynlib"
import "core:sync"
when   ODIN_OS == .Linux \
    || ODIN_OS == .FreeBSD \ 
    || ODIN_OS == .NetBSD \
    || ODIN_OS == .OpenBSD {
        OS_UNIX :: true 
    } else {
        OS_UNIX :: false
    }

InternHashTable :: struct {
    buckets: []InternBucket,
}
InternBucket :: struct {
    strings: [dynamic]^ObjectHeader,
}
String_hashCode: proc "c" (env: ^^JNINativeInterface, this: ^ObjectHeader) -> i32
String_ctor: proc "c" (env: ^^JNINativeInterface, this: ^ObjectHeader, other: ^ObjectHeader)
hashOffset := 0
intern_init :: proc(table: ^InternHashTable) {
    table.buckets = make([]InternBucket, 100)
    for &buck in table.buckets {
        buck.strings = make([dynamic]^ObjectHeader)
    }
}
intern :: proc (internTable: ^InternHashTable, str: ^ObjectHeader) -> ^ObjectHeader {
    if String_hashCode == nil 
    {
        String_hashCode = transmute(proc "c" (env: ^^JNINativeInterface, this: ^ObjectHeader) -> i32)find_method(str.class, "hashCode", "()I").jitted_body
        String_ctor = transmute(proc "c" (env: ^^JNINativeInterface, this: ^ObjectHeader, other: ^ObjectHeader))find_method(str.class, "<init>", "(Ljava/lang/String;)V").jitted_body
        hashOffset = (int)(find_field(str.class, "hash").offset)
    }
    buck := &internTable.buckets[abs(int(String_hashCode(&vm.jni_env, str))) % len(internTable.buckets)]
    res := bucket_add_or_get_string(buck, str)
    return res
}
bucket_add_or_get_string :: proc(bucket: ^InternBucket, str: ^ObjectHeader) -> ^ObjectHeader {
    find_str :: proc(list: [dynamic]^ObjectHeader, hash: i32, str: ^ObjectHeader) -> ^ObjectHeader {
        nstr := javaString_to_string(str)
        defer delete(nstr)
        for item in list {
            itemHash := (transmute(^i32)(transmute(int)item + hashOffset))^
            if hash == itemHash {
                itemstr := javaString_to_string(item)
                defer delete(itemstr)
                if nstr == itemstr do return item

            }
            else do continue
        }
        return nil
    }
    find_index :: proc(list: [dynamic]^ObjectHeader, hash: i32) -> int {
        low := 0
        high := len(list) - 1
        for low <= high {
            mid := (low + high) / 2
            itemHash := (transmute(^i32)(transmute(int)list[mid] + hashOffset))^
            if itemHash < hash {
                low = mid + 1
            } else if itemHash == hash {
                return mid
            } else {
                high = mid - 1
            }
        }
        return 0
    }

    hash := String_hashCode(&vm.jni_env, str)
    found := find_str(bucket.strings, hash, str) 
    if len(bucket.strings) == 0 {
        newstr: ^ObjectHeader = nil
        gc_alloc_object(vm, str.class, &newstr)
        String_ctor(&vm.jni_env, newstr, str)
        String_hashCode(&vm.jni_env, newstr)
        append(&bucket.strings, newstr)
        return newstr
    }
    else if found == nil {
        i := find_index(bucket.strings, hash) 
        newstr: ^ObjectHeader = nil
        gc_alloc_object(vm, str.class, &newstr)
        String_ctor(&vm.jni_env, newstr, str)
        String_hashCode(&vm.jni_env, newstr)
        inject_at(&bucket.strings, i, newstr)
        return newstr
    }
    return found
}

@(thread_local)
current_tid: int
VM :: struct {
    classpaths: []string,
    classes: map[string]^Class,
    lambdaclasses: map[string]^Class,
    object: ^Class,
    ctx: runtime.Context,
    gc: ^GC,
    natives_table: map[^Method][^]u8,
    libraries: [dynamic]dynlib.Library,
    native_intitializers: map[string]proc(),
    classobj_to_class_map: map[^ObjectHeader]^Class,
    exe_allocator: ExeAllocator,
    internTable: InternHashTable,
    jni_env: ^JNINativeInterface,
    stacktraces: map[int][dynamic]^StackEntry,
    monitor: Monitor,
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
hasAnyFlags :: proc(flags_val: $T, flags: ..T) -> bool 
    where intrinsics.type_is_enum(T) {
    for flag in flags {
        if hasFlag(flags_val, flag) {
            return true
        }
    }
    return false
}

javaString_to_string :: proc(str: ^ObjectHeader) -> string {
    charsArray  := transmute(^ArrayHeader)(get_object_field_ref(str, "value")^)
    chars := array_to_slice(u16, charsArray)
    utf8_str := make([]u8, len(chars) * 2)
    defer delete(utf8_str)
    n := utf16.decode_to_utf8(utf8_str, chars)
    return strings.clone_from_bytes(utf8_str[:n])
    
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
            typ.monitor.count = 0
            typ.monitor.tid = 0
            typ.monitor.mutex = {}
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
            type.monitor.count = 0
            type.monitor.tid = 0
            type.monitor.mutex = {}
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
        fmt.println("no entry", file_name)
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
replace_body :: proc(vm: ^VM, method: ^Method, procptr: rawptr) {

    monitor_enter(vm, &vm.monitor)
    defer monitor_exit(vm, &vm.monitor)
    using x86asm
    assembler := Assembler {}
    init_asm(&assembler)
    defer delete_asm(&assembler)
    mov(&assembler, Reg64.Rax, transmute(int)procptr)
    jmp(&assembler, Reg64.Rax)
    if method.jitted_body != nil {
         executable_free(&vm.exe_allocator, method.jitted_body)
    }
    method.jitted_body = exealloc_alloc(&vm.exe_allocator, len(assembler.bytes))
    for b, i in assembler.bytes {
        method.jitted_body[i] = b
    }
}
load_class :: proc(vm: ^VM, class_name: string) -> shared.Result(^Class, string) {
    using classparser
    using shared 
    monitor_enter(vm, &vm.monitor)
    defer monitor_exit(vm, &vm.monitor)
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
                if file_exists(fullpath) {
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
            if classname == nil {
                return Err(^Class, fmt.aprintf("Could not find class %s", class_name))
            }
            class := new(Class)
            class.monitor.count = 0
            class.monitor.tid = 0
            class.monitor.mutex = {}
            class.strings = make(map[u16]^ObjectHeader)
            class.class_file = classfile
            class.access_flags = classfile.access_flags
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
                fld.descriptor = typ.(string)
                fld.name = name.(string)
                //t, _ := type_descriptor_to_type(vm, typ.(string))
                //if t.is_err {
                    //return t
                //}
                //fld.type = t.value.(^Class)
                class.fields[i] = fld
                if !hasFlag(fld.access_flags, MemberAccessFlags.Static) {
                    append(&instance_fields, &class.fields[i]) 
                }

            }
            class.instance_fields = instance_fields[:]
            calculate_class_size(class)
            determine_if_class_is_finalizable(class)
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
                //err := parse_method_descriptor(vm, &meth, typ.(string))
                //if err != nil {
                    //return Err(^Class, err.(string))
                //}
                meth.parent = class
                meth.jitted_body = nil
                class.methods[i] = meth

                
            }
            init := vm.native_intitializers[class.name]
            if init != nil { init() }
            for &method in class.methods {
                if !hasFlag(method.access_flags, classparser.MethodAccessFlags.Abstract) && method.jitted_body == nil {
                    prepare_lazy_bootstrap(vm, &method)
                }
                if method.name == "<init>" && method.descriptor == "()V" {
                    check_if_empty_init(&method) 
                }
            }
            gc_add_field_roots(vm.gc, class)
            return Ok(string, class) 
        }
    }
    return Err(^Class, fmt.aprintf("Could not find class %s", class_name))
}
check_if_empty_init :: proc(method: ^Method) {
    if method.parent.name == "java/lang/Object" {
        method.empty_init = true
        return
    }
    code := method.code.(classparser.CodeAttribute)
    if len(code.code) != 3 do return
    if s, ok := code.code[0].(classparser.SimpleInstruction); ok {
        if s.opcode != .aload || s.operand.(classparser.OneOperand).op != 0 do return
        if s1, ok := code.code[1].(classparser.SimpleInstruction); ok {
            if s1.opcode != .invokespecial do return 
            base := s1.operand.(classparser.OneOperand).op 
            basemethod := classparser.resolve_methodref(method.parent.class_file, u16(base)).(classparser.MethodRefInfo)
            basename := classparser.resolve_class_name(method.parent.class_file, basemethod.class_index).(string)
            if basename != method.parent.super_class.name do return
            name_and_type := classparser.resolve_name_and_type(method.parent.class_file, basemethod.name_and_type_index).(classparser.NameAndTypeInfo)
            name := classparser.resolve_utf8(method.parent.class_file, name_and_type.name_index).(string)
            descriptor := classparser.resolve_utf8(method.parent.class_file, name_and_type.descriptor_index).(string)
            if name != "<init>" || descriptor != "()V" do return
            baseinit := find_method(method.parent.super_class, name, descriptor)
            if baseinit.empty_init == false do return
            if s2, ok := code.code[2].(classparser.SimpleInstruction); ok {
                if s2.opcode != ._return do return 
                method.empty_init = true
            } else do return
        } else do return

    } else do return 
}
bootstrap_before_jitted: [^]u8 = nil
bootstrap_after_jitted: [^]u8 = nil
prepare_before_jitted :: proc(vm: ^VM) {
    using x86asm
    assembler := Assembler {}
    init_asm(&assembler, false)
    defer delete_asm(&assembler)
//     int3(&assembler)
    subsx(&assembler, rsp, 8)
    for reg in parameter_registers {
        push(&assembler, reg)
    }
    mov(&assembler, rax, r10)
    mov(&assembler, r10, rsp)
    subsx(&assembler, rsp, i32(64))
    for xmmreg in 0..=7 {
        subsx(&assembler, r10, i32(8))
        movsd_mem64_xmm(&assembler, at(r10), Xmm(xmmreg))
    }
    mov(&assembler, parameter_registers[0], transmute(int)vm)
    mov(&assembler, parameter_registers[1], rax)
    mov(&assembler, parameter_registers[2], int(0))
    mov(&assembler, rax, transmute(int)jit_method_lazy)
    mov(&assembler, r10, transmute(int)bootstrap_after_jitted)
    push(&assembler, r10)
    jmp(&assembler, rax)

    bootstrap_before_jitted = exealloc_alloc(&vm.exe_allocator, len(assembler.bytes))
    for b, i in assembler.bytes {
        bootstrap_before_jitted[i] = b
    }
}
prepare_after_jitted :: proc(vm: ^VM) {
    using x86asm
    assembler := Assembler {}
    init_asm(&assembler, false)
    defer delete_asm(&assembler)
    regi := len(parameter_registers) - 1
    xmmreg := 7
    mov(&assembler, r10, rsp)
    for xmmreg >= 0{
        movsd_xmm_mem64(&assembler, Xmm(xmmreg), at(r10))
        addsx(&assembler, r10, i32(8))
        xmmreg -= 1
    }
    addsx(&assembler, rsp, 64)
    for regi >= 0 {
        pop(&assembler, parameter_registers[regi])
        regi -= 1
    }
    addsx(&assembler, rsp, 8)
    jmp(&assembler, rax)

    bootstrap_after_jitted = exealloc_alloc(&vm.exe_allocator, len(assembler.bytes))
    for b, i in assembler.bytes {
        bootstrap_after_jitted[i] = b
    }
}
prepare_lazy_bootstrap :: proc(vm: ^VM, method: ^Method) {
    using x86asm
    assembler := Assembler {}
    init_asm(&assembler, false)
    defer delete_asm(&assembler)
    mov(&assembler, r10, transmute(int)method)
    mov(&assembler, rax, transmute(int)bootstrap_before_jitted)
    jmp(&assembler, rax)

    method.jitted_body = exealloc_alloc(&vm.exe_allocator, len(assembler.bytes))
    for b, i in assembler.bytes {
        method.jitted_body[i] = b
    }
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
    return Err(^Class, "Invalid type descriptor"), 0
}
determine_if_class_is_finalizable :: proc(class: ^Class) {
    if class.name == "java/lang/Object" {
        class.is_finalizable = false
    } else {
        class.is_finalizable = class.super_class.is_finalizable || find_method(class, "finalize", "()V") != nil
    }
}
calculate_class_size :: proc(class: ^Class) {
    size := 0 
    if class.super_class != nil && class.super_class.instance_fields != nil && len(class.super_class.instance_fields) > 0 {
        if class.super_class.size == 0 {
            calculate_class_size(class.super_class)
        }
    }
    startoffset := class.super_class == nil ? size_of(ObjectHeader) : i32(class.super_class.size)
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
        #partial switch _ in const {
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
            case FloatInfo:
                fmt.fprintf(file, "float %f", const.(classparser.FloatInfo).value)
            case DoubleInfo:
                fmt.fprintf(file, "double %f", const.(classparser.DoubleInfo).value)
            case InterfaceMethodRefInfo:
                mref := const.(InterfaceMethodRefInfo)
                class_name := resolve_class_name(classfile, mref.class_index)
                name_and_type := resolve_name_and_type(classfile, mref.name_and_type_index).(NameAndTypeInfo)
                name := resolve_utf8(classfile, name_and_type.name_index)
                type := resolve_utf8(classfile, name_and_type.descriptor_index)
                fmt.fprintf(file, "interface method %s.%s:%s", class_name, name, type)
            case InvokeDynamicInfo:
                fmt.fprintf(file, "invokedynamic")
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
        case .invokespecial, .invokestatic, .invokeinterface, .invokedynamic, .new, .putfield, .putstatic, .newarray, .getfield, .getstatic, .invokevirtual, .ldc, .ldc_w, .ldc2_w, .instanceof,
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
    switch _ in instr {
        case SimpleInstruction: {
            opcode := instr.(SimpleInstruction).opcode
            fmt.fprintf(file, "%s%3i: %s ",tab, instr.(SimpleInstruction).offset, opcode) 
            switch _ in instr.(SimpleInstruction).operand {
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
vm_load_library :: proc(vm: ^VM, lib: string) -> bool {
    monitor_enter(vm, &vm.monitor)
    defer monitor_exit(vm, &vm.monitor)
    switch lib {
        case "libnet.so":
            return true
        case: 
            library, ok := dynlib.load_library(lib)  
            if !ok do return false
            append(&vm.libraries, library)
            return true
    }
}


