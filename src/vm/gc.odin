package vm
import "core:mem"
import "core:unicode/utf16"
import "core:slice"
import "core:fmt"


DEFAULT_CHUNK_SIZE :: 1024 * 128 
GC_ALLIGNMENT :: 128

ObjectHeader :: struct {
    class: ^Class,
    size: int,
}
ArrayHeader :: struct {
    obj: ObjectHeader,
    length: int,
}
FreePlace :: struct {
    chunk: ^Chunk,
    offset: int,
    size: int,
}
Chunk :: struct {
    data: rawptr,
    size: int,
}
GC :: struct {
    chunks: [dynamic]^Chunk,
    free_places: [dynamic]FreePlace,
    temp_roots: [dynamic]^ObjectHeader,
}

gc_find_freeplace :: proc(using gc: ^GC, size: int) -> Maybe(FreePlace) {
    for i in 0..<len(gc.free_places) {
        place := &gc.free_places[i]
        if place.size == size {
            res := place^
            remove_range(&gc.free_places, i, i + 1)
            return res
        }
        else if place.size > size {
            res: FreePlace = { place.chunk, place.offset, size }
            place.offset += size
            place.size -= size
            return res
        }
    }
    return nil
}
gc_init :: proc(using gc: ^GC) {
    gc.chunks = make([dynamic]^Chunk)
    gc.free_places = {}
    gc.free_places = make([dynamic]FreePlace)
    gc.temp_roots = make([dynamic]^ObjectHeader)
    gc_new_chunk(gc)
}
gc_new_chunk :: proc(using gc: ^GC, size: int = DEFAULT_CHUNK_SIZE) {
    data, err := mem.alloc(size, GC_ALLIGNMENT)
    if err != .None {
        panic("Failed to allocate memory")
    }    
    chunk := new(Chunk)
    chunk.data = data
    chunk.size = size
    freeplace := FreePlace { chunk, 0, size }
    append(&chunks, chunk)
    append(&gc.free_places, freeplace)
}

gc_collect :: proc "c" (gc: ^GC) {
    
}
align_size :: proc (size: $T, alignment := GC_ALLIGNMENT) -> T {
    return size % T(alignment) == 0 ? size : size + T(alignment) - size % T(alignment)
}
gc_alloc_object :: proc "c" (vm: ^VM, class: ^Class, output: ^^ObjectHeader, size: int = -1) {
    context = vm.ctx
    objsize := align_size(size == -1 ? class.size : size)
    objplace := gc_find_freeplace(vm.gc, objsize)
    if objplace == nil {
        gc_collect(vm.gc)
        objplace = gc_find_freeplace(vm.gc, objsize)
        if objplace == nil {
            newchunksize := objsize > DEFAULT_CHUNK_SIZE ? align_size(objsize, DEFAULT_CHUNK_SIZE) : DEFAULT_CHUNK_SIZE
            gc_new_chunk(vm.gc, newchunksize)
            objplace = gc_find_freeplace(vm.gc, objsize)
            if objplace == nil {
                panic("")
            }
        }
    }
    


    obj := transmute(^ObjectHeader)(transmute(int)objplace.(FreePlace).chunk.data + objplace.(FreePlace).offset)
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
find_field :: proc "c" (class: ^Class, field_name: string) -> ^Field {
    for &field in class.instance_fields {
        if field.name == field_name {
            return field
        }
    }
    if class.super_class != nil {
        return find_field(class.super_class, field_name)
    }
    return nil
}
get_object_field :: proc "c" (object: ^ObjectHeader, field_name: string) -> int {
    field := find_field(object.class, field_name)
    if field == nil {
        context = {}
        panic("Unknown field")
    }
    return (transmute(^int)(transmute(int)object + cast(int)field.offset))^ 
}
array_to_slice :: proc($T: typeid, array: ^ArrayHeader) -> []T {
    return slice.from_ptr(transmute(^T)(transmute(int)array + size_of(ArrayHeader)), array.length)
}
set_object_field :: proc(object: ^ObjectHeader, field_name: string, raw_data: int) {
    field := find_field(object.class, field_name)
    if field == nil {
        context = {}
        panic("Unknown field")
    }
    (transmute(^int)(transmute(int)object + cast(int)field.offset))^ = raw_data
}
