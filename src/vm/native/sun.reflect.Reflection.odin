package native
import kava "kava:vm"
/// getCallerClass ()Ljava/lang/Class;

Reflection_getCallerClass :: proc "c" () -> ^kava.ObjectHeader {
    context = vm.ctx
    entry := kava.stacktrace[len(kava.stacktrace) - 1]
    return kava.get_class_object(vm, entry.method.parent)
}
/// getClassAccessFlags (Ljava/lang/Class;)I
Reflection_getClassAccessFlags :: proc "c" (class: ^kava.ObjectHeader) -> i32 {
    using kava
    context = vm.ctx
    class := vm.classes[javaString_to_string(get_object_field_ref(class, "name")^)]
    return i32(class.access_flags)
}
