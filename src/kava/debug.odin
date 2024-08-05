package kava
import "core:fmt"
import "core:strings"
import "kava:classparser"
import kavavm "kava:vm"

@(export)
@(link_name = "print_java_string")
print_java_string :: proc "c" (str: ^kavavm.ObjectHeader) {
	context = kavavm.vm.ctx
	strin := kavavm.javaString_to_string(str)
	fmt.printf("%s\n", strin)
}
read_at_offset :: proc(rbp: uintptr, offset: uintptr) -> uintptr {
	return (transmute(^uintptr)(rbp + offset))^
}
print_local_info :: proc(arg: ^kavavm.Class, value: uintptr) {
    using kavavm
	value := value
	if arg.name == "java/lang/String" {
		if value == 0 {
			fmt.printf("String (null)\n")
		} else {
			str := javaString_to_string(transmute(^ObjectHeader)value)
			fmt.printf("String \"%s\"\n", str)
		}
	} else if arg.name == "float" {
		fmt.printf("%s %f\n", arg.name, (transmute(^f32)&value)^)
	} else if arg.name == "double" {
		fmt.printf("%s %f\n", arg.name, (transmute(^f64)&value)^)
	} else {
		fmt.printf("%s %x\n", arg.name, value)
	}
}
@(export)
@(link_name = "print_locals")
print_locals :: proc "c" (class: cstring, method: cstring, descriptor: cstring, rbp: uintptr) {
	using kavavm
	context = vm.ctx
	class := strings.clone_from_cstring(class)
	method := strings.clone_from_cstring(method)
	descriptor := strings.clone_from_cstring(descriptor)
	defer {
		delete(class)
		delete(method)
		delete(descriptor)
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
		value := read_at_offset(rbp, -offset)
		fmt.printf("arg %i: ", i)
		print_local_info(arg, value)
		offset += 8
		i += 1
	}
	for i < methodi.max_locals {
		value := read_at_offset(rbp, -offset)
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

@(export)
@(link_name = "print_stack")
print_stack :: proc "c" (class: cstring, method: cstring, descriptor: cstring, rbp: uintptr) {
	using kavavm
	context = vm.ctx
	class := strings.clone_from_cstring(class)
	method := strings.clone_from_cstring(method)
	descriptor := strings.clone_from_cstring(descriptor)
	defer {
		delete(class)
		delete(method)
		delete(descriptor)
	}

	clas := vm.classes[class]
	methodi := find_method(clas, method, descriptor)
    max_stack := int(methodi.code.(classparser.CodeAttribute).max_stack)
	offset: uintptr = 0
    stack_base := uintptr(methodi.stack_base) 
	i := 0
	//if !hasFlag(methodi.access_flags, classparser.MethodAccessFlags.Static) {
		//i += 1
		//offset += 8
	//}

	for i < max_stack {
		value := read_at_offset(rbp, stack_base - offset)
		fmt.printf("stack %i: ", i)
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
@export
@(link_name="as_class")
as_class :: proc "c" (ptr: uintptr) -> ^kavavm.Class {
    return transmute(^kavavm.Class)ptr
}
@export
@(link_name="as_obj")
as_obj :: proc "c" (ptr: uintptr) -> ^kavavm.ObjectHeader {
    return transmute(^kavavm.ObjectHeader)ptr
}
@export
@(link_name="as_array")
as_array :: proc "c" (ptr: uintptr) -> ^kavavm.ArrayHeader {
    return transmute(^kavavm.ArrayHeader)ptr
}

@export
@(link_name="get_field")
get_field :: proc "c" (ptr: uintptr, field: cstring) -> ^kavavm.ObjectHeader {
    context = kavavm.vm.ctx
    field := strings.clone_from_cstring(field)
    defer delete(field)
    return transmute(^kavavm.ObjectHeader)kavavm.get_object_field(transmute(^kavavm.ObjectHeader)ptr, field)
}

