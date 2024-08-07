package native
import kava "kava:vm"

/// initialize ()V
VM_initialize :: proc "c" () {}
/// <clinit> ()V replace
VM_clinit :: proc "c" () {}

/// getSavedProperty (Ljava/lang/String;)Ljava/lang/String; replace
VM_getSavedProperty :: proc "c" (prop: ^kava.ObjectHeader) -> ^kava.ObjectHeader {
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
