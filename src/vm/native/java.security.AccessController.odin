package native
import kava "kava:vm"

/// doPrivileged (Ljava/security/PrivilegedAction;)Ljava/lang/Object; 
AccessController_doPriviliged :: proc "c" (action: ^kava.ObjectHeader) {
    context = vm.ctx
    using kava
    actionclass := load_class(vm, "java/security/PrivilegedAction").value.(^Class)
    run := transmute(proc "c" (this: ^ObjectHeader) -> ^ObjectHeader)find_method_virtual(action.class, "run", "()Ljava/lang/Object;").jitted_body 
    run(action)
}
