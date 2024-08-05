package kava
import "core:fmt"
import "core:strings"
import "kava:classparser"
import kavavm "kava:vm"

@export
@(link_name="print_java_string")
print_java_string :: proc "c" (str: ^kavavm.ObjectHeader){
    context = kavavm.vm.ctx
    strin := kavavm.javaString_to_string(str)
    fmt.printf("%s\n", strin)
}
@export
@(link_name="print_locals")
print_locals :: proc "c" (class: cstring, method: cstring, descriptor: cstring, rbp: uintptr) {
    using kavavm
    context = vm.ctx
    class  := strings.clone_from_cstring(class)
    method := strings.clone_from_cstring(method)
    descriptor := strings.clone_from_cstring(descriptor)
    defer {
        delete(class)
        delete(method)
        delete(descriptor)
    }

    read_at_offset :: proc (rbp: uintptr, offset: uintptr) -> uintptr {
        return (transmute(^uintptr)(rbp - offset))^
    }
    print_local_info :: proc(arg: ^kavavm.Class, value: uintptr) {
        value := value
        if arg.name == "java/lang/String" {
            if value == 0 {
                fmt.printf("String (null)\n")
            } else {
                str := javaString_to_string(transmute(^ObjectHeader)value) 
                fmt.printf("String \"%s\"\n", str)
            }
        } else if  arg.name == "float" {
            fmt.printf("%s %f\n", arg.name, (transmute(^f32)&value)^)
        } else if  arg.name == "double" {
            fmt.printf("%s %f\n", arg.name, (transmute(^f64)&value)^)
        } else {
            fmt.printf("%s %x\n", arg.name, value)
        }
    }
    clas := vm.classes[class]
    methodi := find_method(clas, method, descriptor)
    offset: uintptr = 0x28 // first 32 byte is used by stacktrace info
    i := 0 
    if !hasFlag(methodi.access_flags, classparser.MethodAccessFlags.Static) {
        i += 1
        offset += 8
    }
    
    for arg in methodi.args {
        value := read_at_offset(rbp, offset)
        fmt.printf("arg %i: ", i)
        print_local_info(arg, value)
        offset += 8
        i+=1
    }
    for i < methodi.max_locals {
        value := read_at_offset(rbp, offset)
        fmt.printf("local %i: ", i)
        if gc_is_alloced_by_gc(vm.gc, transmute(rawptr)value) {
            obj := transmute(^ObjectHeader)value
            print_local_info(obj.class, value)
        } else {
            fmt.println(value)
        }

        offset += 8
        i += 1
    }

}
