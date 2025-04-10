package native
import kava "kava:vm"
import "core:mem"
import "base:intrinsics"
/// registerNatives ()V
Unsafe_registerNatives :: proc "c" (env: ^kava.JNINativeInterface, ) {
    context = vm.ctx
    using kava
//     load_class(vm, "sun/misc/VM").value.(^Class).class_initializer_called = true
}

/// arrayBaseOffset (Ljava/lang/Class;)I 
Unsafe_arrayBaseOffset :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, class: ^kava.ObjectHeader) -> i32 {
    return size_of(kava.ArrayHeader)
}
/// arrayIndexScale (Ljava/lang/Class;)I 
Unsafe_arrayIndexScale :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, class: ^kava.ObjectHeader) -> i32 {
    context = vm.ctx
    classInfo, ok := vm.classobj_to_class_map[class]
    if !ok {
        
        panic("")
    }
    if classInfo.class_type == kava.ClassType.Primitive {
        switch classInfo.primitive {
            case .Int, .Float: return 4
            case .Char, .Short: return 2
            case .Byte, .Boolean: return 1
            case .Long, .Double: return 8
            case .Void: return 0
        }
    }
    return 8
}
/// addressSize ()I
Unsafe_addressSize :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader) -> i32 {
    return 8
}
/// freeMemory (J)V
Unsafe_freeMemory :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, ptr: rawptr) {
    context = vm.ctx
    mem.free(ptr)
}
/// allocateMemory (J)J
Unsafe_allocateMemory :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, size: int) -> rawptr {
    context = vm.ctx
    res, err := mem.alloc(size)  
    return res
}
/// getLong (Ljava/lang/Object;J)J
Unsafe_getLong :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, obj: ^kava.ObjectHeader, offset: int) -> int {
    return (transmute(^int)(transmute(int)obj + offset))^
}


/// putLong (JJ)V
Unsafe_putLong:: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, addr: ^int, value: int) {
    addr^ = value
}
/// getByte (J)B
Unsafe_getByte :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, addr: ^u8) -> u8 {
    return addr^
}
/// compareAndSwapObject (Ljava/lang/Object;JLjava/lang/Object;Ljava/lang/Object;)Z
Unsafe_comapareAndSwapObject :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, obj: ^kava.ObjectHeader, offset: int, expect: ^kava.ObjectHeader, update: ^kava.ObjectHeader) -> bool {
    ptr := transmute(^^kava.ObjectHeader)(transmute(int)obj + offset)
    _, res := intrinsics.atomic_compare_exchange_strong(ptr, expect, update)
    return res
    
}
/// compareAndSwapLong (Ljava/lang/Object;JJJ)Z 
Unsafe_comapareAndSwapLong :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, obj: ^kava.ObjectHeader, offset: int, expect: i64, update: i64) -> bool {
    ptr := transmute(^i64)(transmute(int)obj + offset)
    _, res := intrinsics.atomic_compare_exchange_strong(ptr, expect, update)
    return res
    
}
/// compareAndSwapInt (Ljava/lang/Object;JII)Z 
Unsafe_comapareAndSwapInt :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, obj: ^kava.ObjectHeader, offset: int, expect: i32, update: i32) -> bool {
    ptr := transmute(^i32)(transmute(int)obj + offset)
    _, res := intrinsics.atomic_compare_exchange_strong(ptr, expect, update)
    return res
    
}
/// getIntVolatile (Ljava/lang/Object;J)I
Unsafe_getIntVolatile :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, obj: ^kava.ObjectHeader, offset: int) -> i32 {
    ptr := transmute(^i32)(transmute(int)obj + offset)
    return intrinsics.volatile_load(ptr)
}
/// getObjectVolatile (Ljava/lang/Object;J)Ljava/lang/Object;
Unsafe_getObjectVolatile :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, obj: ^kava.ObjectHeader, offset: int) -> ^kava.ObjectHeader {
    ptr := transmute(^^kava.ObjectHeader)(transmute(int)obj + offset)
    return intrinsics.volatile_load(ptr)
}
/// objectFieldOffset (Ljava/lang/reflect/Field;)J
Unsafe_objectFieldOffset :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, field: ^kava.ObjectHeader) -> i64 {
    using kava
    context = vm.ctx
    class_obj := get_object_field_ref(field, "clazz")^
    name_obj  := get_object_field_ref(field, "name")^


    field_name := javaString_to_string(name_obj)
    defer delete(field_name)

    class := transmute(^Class)get_object_field(class_obj, "handle")
    fld := kava.find_field(class, field_name)
    
    return i64(fld.offset)
}
