package vm
import "kava:classparser"
import "kava:shared"
import "core:os"
import "core:fmt"
import "core:strings"
import "core:path/filepath"
import "zip:zip"

PrimitiveType :: enum {
    Int,
    Char,
    Byte,
    Short,
    Float,
    Double,
    Long,
    Void,
}
ClassType :: enum {
    Class = 0,
    Primitive,
    Array,
}
ArrayType :: struct {
    underlaying: ^Class,
    dimensions: int,
}
Field :: struct {
    name: string,
    type: ^Class,
    access_flags: classparser.AccessFlags,

}
Method :: struct {
    name: string,
    access_flags: classparser.AccessFlags,
    ret_type: ^Class,
    args: []^Class,
    locals: []^Class,
    code: Maybe(classparser.CodeAttribute),
}
Class :: struct {
    name: string,
    super_class: ^Class,
    interfaces: []^Class,
    access_flags: classparser.AccessFlags,
    fields: []Field,
    methods: []Method,
    class_file: ^classparser.ClassFile,
    class_type: ClassType,
    underlaying: ^Class,
    primitive: PrimitiveType,

}
VM :: struct {
    classpaths: []string,
    classes: map[string]^Class,
    primitives: map[PrimitiveType]^Class,
}
primitive_names: map[PrimitiveType]string = {
    PrimitiveType.Int = "int",
    PrimitiveType.Char = "char",
    PrimitiveType.Byte = "byte",
    PrimitiveType.Short = "short",
    PrimitiveType.Float = "float",
    PrimitiveType.Double = "double",
    PrimitiveType.Long = "long",
    PrimitiveType.Void = "void",
}
error :: proc(str: string, args: ..any) {
    fmt.printf(str, ..args)
    fmt.println()
    os.exit(-1)
}
when ODIN_OS == .Linux {
    DIR_SEPARATOR :: ":" 
} else when ODIN_OS == .Windows {
    DIR_SEPARATOR :: ";"
}
print_usage :: proc() {
    fmt.println("usage: kava [-options] class [args...]")
}
uncompress_if_exists :: proc(zip_file_name: string, file_name: string) -> []u8 {
    zip_file := zip.open(zip_file_name, 0, zip.OpenMode.Read)
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
load_class :: proc(vm: ^VM, class_name: string) -> shared.Result(^Class, string) {
    using classparser
    using shared 
    if cl, is_found := vm.classes[class_name]; is_found {
        return Ok(^Class, string, cl)
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
                bytes :=uncompress_if_exists(path, class_file) 
                defer delete(bytes)
                if bytes == nil {
                    continue
                }
                res := classparser.read_class_file(bytes)
                classfile = new_clone(res.value.(ClassFile))

            }
            else {
                if os.exists(fullpath) {
                    bytes, _ := os.read_entire_file(fullpath)
                    defer delete(bytes)
                    classfile = new_clone(read_class_file(bytes).value.(ClassFile))
                }
            }

            classname := resolve_class_name(classfile, classfile.this_class)
            if classname == nil || classname.(string) != class_name {
                return Err(^Class, string, fmt.aprintf("Could not find class %s", class_name))
            }
            class := new(Class)
            class.class_file = classfile
            vm.classes[class_name] = class
            name := resolve_class_name(classfile, classfile.this_class)
            if name == nil {
                delete_class(classfile^)
                free(classfile)
                return Err(^Class, string, fmt.aprintf("Invalid class file %s", class_name))
            }
            super_class_name := resolve_class_name(classfile, classfile.super_class)
            if super_class_name == nil && class_name != "java/lang/Object" {
                delete_class(classfile^)
                free(classfile)
                return Err(^Class, string, fmt.aprintf("Invalid class file %s", class_name))
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
                    return Err(^Class, string, fmt.aprintf("Invalid class file %s", classfile))
                }
                interfac := load_class(vm, ifacename.(string))
                if interfac.is_err {
                    return interfac
                }
                class.interfaces[i] = interfac.value.(^Class)


            }
            class.fields = make([]Field, len(classfile.fields))
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
                fld.type = t
                class.fields[i] = fld

            }
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
                meth.access_flags = method.access_flags
                meth.code = method.bytecode
                parse_method_descriptor(vm, &meth, typ.(string))
                class.methods[i] = meth
                
            }
            return Ok(^Class, string, class) 
        }
    }
    return Err(^Class, string, fmt.aprintf("Could not find class %s", class_name))
}
parse_method_descriptor :: proc(vm: ^VM, method: ^Method, descriptor: string) {
    if len(descriptor) < 2 {
        return
    }
    if descriptor[0] != '(' {
        panic("")
    }
    types := make([dynamic]^Class)
    i := 1
    for descriptor[i] != ')' {
        type, read := type_descriptor_to_type(vm, descriptor[i:])
        append(&types, type)
        i += read
    }
    i += 1
    retType, read := type_descriptor_to_type(vm, descriptor[i:])
    method.ret_type = retType
    method.args = types[:]
}
type_descriptor_to_type :: proc(vm: ^VM, descriptor: string) -> (^Class, int) {
    if len(descriptor) == 0 {
        return nil, 0
    }
    switch descriptor[0] {
        case '[':
            type, read := type_descriptor_to_type(vm, descriptor[1:])    
            index := strings.index_any(descriptor, ";")
            name := descriptor
            if index != -1 {
                name = descriptor[0:index+1]
            }
            return make_array_type(vm, type, name), read + 1
        case 'I': 
            return vm.classes[primitive_names[PrimitiveType.Int]], 1
        case 'C': 
            return vm.classes[primitive_names[PrimitiveType.Char]], 1
        case 'D': 
            return vm.classes[primitive_names[PrimitiveType.Double]], 1
        case 'J': 
            return vm.classes[primitive_names[PrimitiveType.Long]], 1
        case 'V': 
            return vm.classes[primitive_names[PrimitiveType.Void]], 1
        case 'F': 
            return vm.classes[primitive_names[PrimitiveType.Float]], 1
        case 'B': 
            return vm.classes[primitive_names[PrimitiveType.Byte]], 1
        case 'S': 
            return vm.classes[primitive_names[PrimitiveType.Short]], 1
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
                panic(res.error.(string))
            }  else {
                return res.value.(^Class), read
            }
    }
    return nil, 0
}
make_array_type :: proc(vm: ^VM, type: ^Class, name: string) -> ^Class {
    if class, found := vm.classes[name]; found {
        return class
    }
    typ := new(Class) 
    typ.name = name
    typ.class_type = ClassType.Array
    typ.underlaying = type
    vm.classes[name] = typ 
    return typ
} 
make_primitive :: proc(vm: ^VM, primitive: PrimitiveType, name: string) -> ^Class {
    if class, found := vm.classes[name]; found {
        return class
    }
    type := new(Class)
    type.class_type = ClassType.Primitive
    type.name = name
    type.primitive = primitive
    vm.classes[name] = type
    return type
}
main :: proc() {
    args := os.args[1:]
    if len(args) == 0 {
        print_usage()
        return
    }
    classpaths:[]string = nil
    application:string = ""
    applicationargs:[]string = nil
    i := 0
    for i < len(args) {
        switch args[i] {
            case "-cp":
                if i + 1 >= len(args) {
                    error("Error: -cp requires class path specification")
                }  
                classpaths = strings.split(args[i + 1], DIR_SEPARATOR)
                i += 1
            case:
                application = args[i]
                if i + 1 <= len(args) {
                    applicationargs = args[i + 1:]
                }
                i = len(args)
        }
        i += 1
    }
    if application == "" {
        print_usage()
        return
    }
    vm := VM {
        classpaths = classpaths,
        classes = make(map[string]^Class),
        primitives = make(map[PrimitiveType]^Class),
    }

//     vm.classes["java/lang/Object"] = new_clone(Class {})
//     vm.classes["java/lang/Runnable"] = new_clone(Class {})
    fmt.println(load_class(&vm, application).error)
    for k,v in vm.classes {
        fmt.println(k, "=", v)
    }
}
