package native
import kava "kava:vm"
/// getCallerClass ()Ljava/lang/Class;

Reflection_getCallerClass :: proc "c" () -> ^kava.ObjectHeader {
    context = vm.ctx
    entry := kava.stacktrace[len(kava.stacktrace) - 1]
    return kava.get_class_object(vm, entry.method.parent)
}
