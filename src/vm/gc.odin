package vm
import "core:mem"
import "core:unicode/utf16"
import "core:slice"
import "core:fmt"
ObjectHeader :: struct {
    class: ^Class,
    size: int,
}
ArrayHeader :: struct {
    obj: ObjectHeader,
    length: int,
}

gc_alloc_object :: proc "c" (vm: ^VM, class: ^Class, size: int = -1) -> ^ObjectHeader {
    context = vm.ctx
    ptr, err := mem.alloc(size == -1 ? class.size : size)
    assert(err == .None)
    obj := transmute(^ObjectHeader)ptr
    obj.size = size == -1 ? class.size : size
    obj.class = class
    return obj
}
gc_alloc_array ::  proc(vm: ^VM, elem_class: ^Class, elems: int) -> ^ArrayHeader {
    array_type := make_array_type(vm, elem_class) 
    array_obj := transmute(^ArrayHeader)gc_alloc_object(vm, array_type, size_of(ArrayHeader) + elem_class.size * elems)
    array_obj.length = elems 
    return array_obj
}
gc_alloc_string :: proc(vm: ^VM, str: string) -> ^ObjectHeader {
    array := gc_alloc_array(vm, vm.classes["char"], len(str)) 
    chars_start := transmute(^u16)(transmute(int)array + size_of(ArrayHeader))
    chars := slice.from_ptr(chars_start, len(str))
    for c, i in str {
        chars[i] = cast(u16)c
    }
    strobj :=gc_alloc_object(vm, vm.classes["java/lang/String"])
    set_object_field(strobj, "value", transmute(int)array)
    set_object_field(strobj, "length", len(chars))
    set_object_field(strobj, "offset", 0)
    return strobj
}

get_object_field :: proc(object: ^ObjectHeader, field_name: string) -> int {
    for field in object.class.instance_fields {
        if field.name == field_name {
            return (transmute(^int)(transmute(int)object + cast(int)field.offset))^ 
        }
    }
    panic("Unknown field")
}
array_to_slice :: proc($T: typeid, array: ^ArrayHeader) -> []T {
    return slice.from_ptr(transmute(^T)(transmute(int)array + size_of(ArrayHeader)), array.length)
}
set_object_field :: proc(object: ^ObjectHeader, field_name: string, raw_data: int) {
    for field in object.class.instance_fields {
        if field.name == field_name {
            (transmute(^int)(transmute(int)object + cast(int)field.offset))^ = raw_data
            return
        }
    }
    panic("Unknown field")
}
