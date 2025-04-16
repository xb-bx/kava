package native
import kava "kava:vm"

/// initialize ()V
VM_initialize :: proc "c" (env: ^^kava.JNINativeInterface, ) {}
/// <clinit> ()V replace
VM_clinit :: proc "c" (env: ^^kava.JNINativeInterface, ) {}

/// getSavedProperty (Ljava/lang/String;)Ljava/lang/String; replace
VM_getSavedProperty :: proc "c" (env: ^^kava.JNINativeInterface, prop: ^kava.ObjectHeader) -> ^kava.ObjectHeader {
    context = vm.ctx
    prop_str := kava.javaString_to_string(prop)
    defer delete(prop_str)
    if prop_str == "java.lang.Integer.IntegerCache.high" {
        res: ^kava.ObjectHeader = nil
        kava.gc_alloc_string(vm, "127", &res)
        return res
    }
    else do panic("unimplemented")
    return nil
     
}
