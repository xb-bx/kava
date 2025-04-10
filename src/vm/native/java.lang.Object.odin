package native
import kava "kava:vm"
import "core:fmt"
import "core:mem"

/// registerNatives ()V
Object_registerNatives :: proc "c" (env: ^kava.JNINativeInterface, ) {}
/// hashCode ()I
hashCode :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader) -> i32 {
    return cast(i32)transmute(int)this
}

/// getClass ()Ljava/lang/Class;
Object_getClass :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader) -> ^kava.ObjectHeader {
    context = vm.ctx
    return kava.get_class_object(vm, this.class)
}
/// clone ()Ljava/lang/Object;
Object_clone :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader) -> ^kava.ObjectHeader {
    using kava
    context = vm.ctx
    if this.class.class_type == ClassType.Array {
        this_array := transmute(^ArrayHeader)this
        new_array : ^ArrayHeader = nil
        gc_alloc_array(vm, this.class.underlaying, this_array.length, &new_array)
        arraycopy(env, this_array, 0, new_array, 0, i32(this_array.length))
        return transmute(^ObjectHeader)new_array
    }
    else {
        cloneable := load_class(vm, "java/lang/Cloneable").value.(^Class)
        if is_subtype_of(this.class, cloneable) {
            new_obj: ^ObjectHeader = nil
            gc_alloc_object(vm, this.class, &new_obj)
            dest := transmute(rawptr)(transmute(int)new_obj + size_of(ObjectHeader))
            src := transmute(rawptr)(transmute(int)this + size_of(ObjectHeader))
            mem.copy(dest, src, this.class.size_without_header)
            return new_obj
        }
        else {
            error := fmt.aprintf("Class %s does not implements Cloneable interface", this.class.name, allocator = context.temp_allocator)
            throw_exception_string(vm, "java/lang/CloneNotSupportedException", error)
        }
    }
    return nil
}

