package native
import kava "kava:vm"
import "core:mem"
/// registerNatives ()V
Unsafe_registerNatives :: proc "c" () {
    context = vm.ctx
    using kava
//     load_class(vm, "sun/misc/VM").value.(^Class).class_initializer_called = true
}

/// arrayBaseOffset (Ljava/lang/Class;)I 
Unsafe_arrayBaseOffset :: proc "c" (this: ^kava.ObjectHeader, class: ^kava.ObjectHeader) -> i32 {
    return size_of(kava.ArrayHeader)
}
/// arrayIndexScale (Ljava/lang/Class;)I 
Unsafe_arrayIndexScale :: proc "c" (this: ^kava.ObjectHeader, class: ^kava.ObjectHeader) -> i32 {
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
Unsafe_addressSize :: proc "c" (this: ^kava.ObjectHeader) -> i32 {
    return 8
}
/// freeMemory (J)V
Unsafe_freeMemory :: proc "c" (this: ^kava.ObjectHeader, ptr: rawptr) {
    context = vm.ctx
    mem.free(ptr)
}
/// allocateMemory (J)J
Unsafe_allocateMemory :: proc "c" (this: ^kava.ObjectHeader, size: int) -> rawptr {
    context = vm.ctx
    res, err := mem.alloc(size)  
    return res
}
/// getLong (Ljava/lang/Object;J)J
Unsafe_getLong :: proc "c" (this: ^kava.ObjectHeader, obj: ^kava.ObjectHeader, offset: int) -> int {
    return (transmute(^int)(transmute(int)obj + offset))^
}


/// putLong (JJ)V
Unsafe_putLong:: proc "c" (this: ^kava.ObjectHeader, addr: ^int, value: int) {
    addr^ = value
}
/// getByte (J)B
Unsafe_getByte :: proc "c" (this: ^kava.ObjectHeader, addr: ^u8) -> u8 {
    return addr^
}

