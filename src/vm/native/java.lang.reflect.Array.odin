package native
import kava "kava:vm"

/// newArray (Ljava/lang/Class;I)Ljava/lang/Object;
Array_newArray  :: proc "c" (env: ^^kava.JNINativeInterface, component: ^kava.ObjectHeader, length: i32) -> ^kava.ArrayHeader {
    using kava
    context = vm.ctx
    class := transmute(^Class)get_object_field(component, "handle")
    res: ^ArrayHeader = nil
    gc_alloc_array(vm, class, int(length), &res)
    return res
}
