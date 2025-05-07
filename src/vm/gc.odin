package vm
import "core:mem"
import "core:sync"
import "core:unicode/utf16"
import "core:slice"
import "core:fmt"
import "kava:classparser"
import "base:runtime"
import "core:time"
import "core:unicode/utf8"


DEFAULT_CHUNK_SIZE :: 1 * 1024 * 1024 
GC_ALLIGNMENT :: 128

ObjectHeaderGCFlags :: enum int {
    Marked = 0x0001,
    Frozen = 0x0002,
    Finalizing = 0x0004,
    Finalized = 0x0008,
}
ObjectHeader :: struct {
    class: ^Class,
    size: int,
    flags: ObjectHeaderGCFlags,
    monitor: Monitor,
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
    roots: [dynamic]^^ObjectHeader,
}

gc_total_memory :: proc(using gc: ^GC) -> i64 {
    sum: i64 = 0
    for chunk in chunks {
        sum += i64(chunk.size)
    }
    return sum
}
@(private="file")
gc_find_freeplace :: proc(using gc: ^GC, size: int) -> Maybe(FreePlace) {
    for i in 0..<len(gc.free_places) {
        place := &gc.free_places[i]
        if size == place.size {
            res := place^
            remove_range(&gc.free_places, i, i + 1)
            return res
        }
        else if place.size > size && place.size - size >= GC_ALLIGNMENT {
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
    gc.roots = make([dynamic]^^ObjectHeader)

    gc_new_chunk(gc)
}
@(private="file")
gc_new_chunk :: proc(using gc: ^GC, size: int = DEFAULT_CHUNK_SIZE) {
    data, err := mem.alloc(size, GC_ALLIGNMENT)
    if err != .None {
        fmt.println(err, size)
        print_stack_trace()
        panic("Failed to allocate memory")

    }    
    fmt.println("new chunk", size)
    
    chunk := new(Chunk)
    chunk.data = data
    chunk.size = size
    freeplace := FreePlace { chunk, 0, size }
    append(&chunks, chunk)
    append(&gc.free_places, freeplace)
}

gc_add_field_roots :: proc(gc: ^GC, class: ^Class) {
    for &fld in class.fields {
        if hasFlag(fld.access_flags, classparser.MemberAccessFlags.Static) {
            append(&gc.roots, transmute(^^ObjectHeader)&fld.static_data)                     
        }
        append(&gc.roots, &fld.field_obj)
    }
}
@(private="file")
gc_is_ptr_inbounds_of :: proc(chunk: ^Chunk, ptr: rawptr, alignment := GC_ALLIGNMENT) -> bool {
    start := transmute(int)chunk.data 
    end := start + chunk.size
    iptr := transmute(int)ptr
    if (iptr - start) % alignment != 0 {
        return false 
    }
    return iptr >= start && iptr < end
}
gc_is_alloced_by_gc :: proc(gc: ^GC, ptr: rawptr) -> bool {
    return gc_chunk_of_pointer(gc, ptr) != nil
}
@(private="file")
gc_chunk_of_pointer :: proc(gc: ^GC, ptr: rawptr) -> ^Chunk {
    for chunk in gc.chunks {
        if(gc_is_ptr_inbounds_of(chunk, ptr)) {
            return chunk
        }
    }
    return nil
}
@(private="file")
gc_visit_obj :: proc(gc: ^GC, obj: ^ObjectHeader, class: ^Class = nil) {
    if hasAnyFlags(obj.flags, ObjectHeaderGCFlags.Marked, ObjectHeaderGCFlags.Finalizing) && class == nil { return }
    obj.flags |= ObjectHeaderGCFlags.Marked
    class := class
    if class == nil {
        class = obj.class
    }
    if class.super_class != nil {
        gc_visit_obj(gc, obj, class.super_class)
    }
    if class.class_type == ClassType.Class {
        for fld in class.fields {
            if hasFlag(fld.access_flags, classparser.MemberAccessFlags.Static) {
                continue
            }
//             fmt.println("visiting fld", fld.name, fld.type.name)
            gc_visit_ptr(gc, (transmute(^rawptr)(transmute(int)obj + int(fld.offset)))^)
        }
    } else if class.class_type == ClassType.Array {
        array := transmute(^ArrayHeader)obj  
        if class.underlaying.class_type == ClassType.Primitive {
            return
        } else {

            arrayslice := array_to_slice(rawptr, array)
            for ptr in arrayslice  {
//                 ptr := transmute([^]rawptr)(transmute(int)array + size_of(ArrayHeader))
                gc_visit_ptr(gc, ptr)
            }
        }
    }
}
@(private="file")
gc_visit_ptr :: proc(gc: ^GC, root: rawptr) {
    chunk := gc_chunk_of_pointer(gc, root) 
    if chunk == nil {
        return 
    }

    objheader := transmute(^ObjectHeader)root
//     fmt.println("success visit ptr", objheader.class.name)
    gc_visit_obj(gc, objheader)
}
@(private="file")
gc_visit_roots :: proc(using vm: ^VM) {
    for root in gc.roots {
        gc_visit_ptr(gc, transmute(rawptr)root^)

    }
    for root in gc.temp_roots {
        gc_visit_ptr(gc, transmute(rawptr)root)
    }
    for internBucket in internTable.buckets {
        for str in internBucket.strings {
            gc_visit_ptr(gc, str)

        }
    }
    
}
gc_visit_stack :: proc(vm: ^VM) {
    gc := vm.gc
    for _, entry in vm.stacktraces {
        e := entry 
        for e in entry {
            i := e.rbp - e.size
            for i < e.rbp  {
                gc_visit_ptr(gc, (transmute(^rawptr)i)^) 
                i += 8
            }     
        }
    }
}
@(private="file")
gc_mark_all_objects :: proc (gc: ^GC) {
    gc_visit_roots(vm)
    gc_visit_stack(vm)
    for obj in objects_to_finalize {
        gc_visit_obj(gc, obj)
    }
}
objects_to_finalize : = make([dynamic]^ObjectHeader)
collection_depth := 0
@(private="file")
gc_collect :: proc (gc: ^GC) {
    stopwatch := time.Stopwatch {}
    time.stopwatch_start(&stopwatch)
    //if true { return }

    //defer delete(objects_to_finalize)
    if collection_depth != 0 {
        return
    }
    collection_depth += 1 
    gc_mark_all_objects(gc)
    objs := make([dynamic]^ObjectHeader)
        
    //objs.
    for chunk in gc.chunks {
        i := 0
        for i < (chunk.size) {
            obj := transmute(^ObjectHeader)(transmute(int)chunk.data + i)
            if(obj.class == nil) {
                i += GC_ALLIGNMENT
                continue;
            }
            if !hasAnyFlags(obj.flags, ObjectHeaderGCFlags.Marked,ObjectHeaderGCFlags.Frozen, ObjectHeaderGCFlags.Finalizing, ObjectHeaderGCFlags.Finalized) && obj.class.is_finalizable {
                obj.flags ~= ObjectHeaderGCFlags.Finalizing
                append(&objects_to_finalize, obj) 
            }
            i += align_size(obj.size)
        }
    }
    
    for chunk, chunki in gc.chunks {
        prev: ^FreePlace = nil
        i := 0
        for i < (chunk.size) {
            obj := transmute(^ObjectHeader)(transmute(int)chunk.data + i)
            if(obj.class == nil || hasFlag(obj.flags, ObjectHeaderGCFlags.Finalizing)) {
                i += GC_ALLIGNMENT
                continue;
            }
            if hasFlag(obj.flags, ObjectHeaderGCFlags.Marked) || hasFlag(obj.flags, ObjectHeaderGCFlags.Frozen) {
                obj.flags ~= ObjectHeaderGCFlags.Marked
            }
            else {
                if prev != nil && prev.offset + prev.size == i {
                    prev.size += align_size(obj.size)
                }
                else {
                    append(&gc.free_places, FreePlace {chunk = chunk, offset = i, size = align_size(obj.size)})
                    prev = &gc.free_places[len(gc.free_places) - 1]
                }
                runtime.mem_zero(obj, align_size(obj.size))
            }
            i += align_size(obj.size)
        }
    }
    for obj in objects_to_finalize {
        (transmute(proc "c" (env: ^^JNINativeInterface, object: ^ObjectHeader)) (find_method_virtual(obj.class, "finalize", "()V").jitted_body))(&vm.jni_env, obj)
        obj.flags ~= ObjectHeaderGCFlags.Finalized
        obj.flags ~= ObjectHeaderGCFlags.Finalizing
    }
    clear(&objects_to_finalize)
    collection_depth -= 1
    time.stopwatch_stop(&stopwatch)
    dur := time.duration_milliseconds(time.stopwatch_duration(stopwatch))
    //fmt.println("GC took", dur, "ms")
}
align_size :: proc (size: $T, alignment := GC_ALLIGNMENT) -> T {
    return size % T(alignment) == 0 ? size : size + T(alignment) - size % T(alignment)
}
gc_alloc_object :: proc "c" (vm: ^VM, class: ^Class, output: ^^ObjectHeader, size: i64 = -1) {
    context = vm.ctx
    monitor_enter(vm, &vm.monitor)
    defer monitor_exit(vm, &vm.monitor)
    objsize := align_size(size <= -1 ? class.size : int(size))
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
    obj.size = size <= -1 ? class.size : int(size)
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
    gc_alloc_object(vm, array_type, transmute(^^ObjectHeader)&array_obj, i64(size_of(ArrayHeader) + elem_class.size * elems))
    array_obj.length = elems 
    output^ = array_obj
}
gc_alloc_string :: proc "c" (vm: ^VM, str: string, output: ^^ObjectHeader) {
    context = vm.ctx
    buf := make([]u16, len(str) * 2)
    defer delete(buf)
    encoded := utf16.encode_string(buf, str)

    array :^ArrayHeader = nil
    gc_alloc_array(vm, vm.classes["char"], encoded, &array) 
    array.obj.flags |= ObjectHeaderGCFlags.Frozen
    chars := array_to_slice(u16, array)
    
    for s, i in buf[:encoded] {
        chars[i] = s
    }
    strobj: ^ObjectHeader = nil
    gc_alloc_object(vm, vm.classes["java/lang/String"], &strobj)
    if array.obj.class == nil || array.obj.class.class_type != ClassType.Array { panic("ZHOPA")}
    set_object_field(strobj, "value", transmute(int)array)
//     set_object_field(strobj, "length", len(chars))
//     set_object_field(strobj, "offset", 0)
    output^ = strobj
    array.obj.flags ~= ObjectHeaderGCFlags.Frozen
}
find_field :: proc "c" (class: ^Class, field_name: string) -> ^Field {
    for &field in class.fields {
        if field.name == field_name {
            return &field
        }
    }
    if class.super_class != nil {
        return find_field(class.super_class, field_name)
    }
    return nil
}
get_object_field_ref :: proc "c" (object: ^ObjectHeader, field_name: string) -> ^^ObjectHeader {
    field := find_field(object.class, field_name)
    if field == nil {
        context = {}
        fmt.println(field_name)
        panic("Unknown field")
    }
    return (transmute(^^ObjectHeader)(transmute(int)object + cast(int)field.offset))
}
get_object_field :: proc "c" (object: ^ObjectHeader, field_name: string) -> int {
    return (transmute(^int)get_object_field_ref(object, field_name))^
}
array_to_slice :: proc($T: typeid, array: ^ArrayHeader) -> []T {
    return slice.from_ptr(transmute(^T)(transmute(int)array + size_of(ArrayHeader)), array.length)
}
set_object_field :: proc(object: ^ObjectHeader, field_name: string, raw_data: int) {
    field := find_field(object.class, field_name)
    if field == nil {
        context = {}
        fmt.println(object.class.name, field_name)
        panic("Unknown field")
    }
    (transmute(^int)(transmute(int)object + cast(int)field.offset))^ = raw_data
}
