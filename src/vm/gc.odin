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

gc_alloc_object :: proc "c" (vm: ^VM, class: ^Class, output: ^^ObjectHeader, size: int = -1) {
    context = vm.ctx
    ptr, err := mem.alloc(size == -1 ? class.size : size)
    assert(err == .None)
    obj := transmute(^ObjectHeader)ptr
    obj.size = size == -1 ? class.size : size
    obj.class = class
    output^ = obj
}
array_is_multidimensional :: proc "c" (arrayclass: ^Class) -> bool {
    return arrayclass.underlaying.class_type == ClassType.Array
}
gc_alloc_multiarray ::  proc "c" (vm: ^VM, arrayclass: ^Class, elems: [^]int, output: ^^ArrayHeader) {
    context = vm.ctx
    class := arrayclass
    gc_alloc_array(vm, class.underlaying, elems[0], output)
    if array_is_multidimensional(class.underlaying) {
        for i in 0..<elems[0] { 
            elem := transmute(^^ArrayHeader)(transmute(int)(output^) + size_of(ArrayHeader) + i * size_of(rawptr))
            gc_alloc_multiarray(vm, class.underlaying, shift_c_array(elems, 1), elem)
        }
    } else {
        for i in 0..<elems[0] {
            elem := transmute(^^ArrayHeader)(transmute(int)(output^) + size_of(ArrayHeader) + i * size_of(rawptr))
            gc_alloc_array(vm, class.underlaying.underlaying, elems[1], elem)
        }
    }
}
shift_c_array :: proc(array: [^]$T, shift: int) -> [^]T {
    return transmute([^]T)((transmute(int)array) + shift * size_of(T))
}
gc_alloc_array ::  proc "c" (vm: ^VM, elem_class: ^Class, elems: int, output: ^^ArrayHeader) {
    context = vm.ctx
    array_type := make_array_type(vm, elem_class) 
    array_obj: ^ArrayHeader = nil
    gc_alloc_object(vm, array_type, transmute(^^ObjectHeader)&array_obj, size_of(ArrayHeader) + elem_class.size * elems)
    array_obj.length = elems 
    output^ = array_obj
}
gc_alloc_string :: proc "c" (vm: ^VM, str: string, output: ^^ObjectHeader) {
    context = vm.ctx
    array :^ArrayHeader = nil
    gc_alloc_array(vm, vm.classes["char"], len(str), &array) 
    chars_start := transmute(^u16)(transmute(int)array + size_of(ArrayHeader))
    chars := slice.from_ptr(chars_start, len(str))
    for c, i in str {
        chars[i] = cast(u16)c
    }
    strobj: ^ObjectHeader = nil
    gc_alloc_object(vm, vm.classes["java/lang/String"], &strobj)
    set_object_field(strobj, "value", transmute(int)array)
    set_object_field(strobj, "length", len(chars))
    set_object_field(strobj, "offset", 0)
    output^ = strobj
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
