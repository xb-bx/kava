package native
import kava "kava:vm"
/// getCallerClass ()Ljava/lang/Class;

Reflection_getCallerClass :: proc "c" () -> ^kava.ObjectHeader {
    context = vm.ctx
    stacktrace := vm.stacktraces[kava.current_tid]
    entry := stacktrace[len(stacktrace) - 2]
    return kava.get_class_object(vm, entry.method.parent)
}
/// getClassAccessFlags (Ljava/lang/Class;)I
Reflection_getClassAccessFlags :: proc "c" (env: ^^kava.JNINativeInterface, class: ^kava.ObjectHeader) -> i32 {
    using kava
    context = vm.ctx
    class := transmute(^Class)get_object_field(class, "handle")
    return i32(class.access_flags)
}
/// filterFields (Ljava/lang/Class;[Ljava/lang/reflect/Field;)[Ljava/lang/reflect/Field; replace
Reflection_filterFields :: proc "c" (env: ^^kava.JNINativeInterface, class: ^kava.ObjectHeader, fields: ^kava.ArrayHeader) -> ^kava.ArrayHeader {
    return fields
}
