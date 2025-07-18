package native
import kava "kava:vm"
/// doPrivileged (Ljava/security/PrivilegedExceptionAction;)Ljava/lang/Object; 
AccessController_doPriviliged2 :: proc "c" (env: ^^kava.JNINativeInterface, action: ^kava.ObjectHeader) {
    context = vm.ctx
    using kava
    actionclass := load_class(vm, "java/security/PrivilegedExceptionAction").value.(^Class)
    run := transmute(proc "c" (env: ^^JNINativeInterface, this: ^ObjectHeader) -> ^ObjectHeader)find_method_virtual(action.class, "run", "()Ljava/lang/Object;").jitted_body 
    run(env, action)
}

/// doPrivileged (Ljava/security/PrivilegedAction;)Ljava/lang/Object; 
AccessController_doPriviliged :: proc "c" (env: ^^kava.JNINativeInterface, action: ^kava.ObjectHeader) {
    context = vm.ctx
    using kava
    actionclass := load_class(vm, "java/security/PrivilegedAction").value.(^Class)
    run := transmute(proc "c" (env: ^^JNINativeInterface, this: ^ObjectHeader) -> ^ObjectHeader)find_method_virtual(action.class, "run", "()Ljava/lang/Object;").jitted_body 
    run(env, action)
}
/// getStackAccessControlContext ()Ljava/security/AccessControlContext;
AccessController_getStackAccessControlContext :: proc "c" (env: ^^kava.JNINativeInterface) -> ^kava.ObjectHeader {
    return nil
}
