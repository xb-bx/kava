package native
import kava "kava:vm"
import "core:fmt"

/// longBitsToDouble (J)D
longBitsToDouble :: proc "c"(env: ^^kava.JNINativeInterface, long: i64) -> f64 {
    return transmute(f64)long
}
/// doubleToRawLongBits (D)J
doubleToRawLongBits :: proc "c" (env: ^^kava.JNINativeInterface, double: f64) -> i64 {
    return transmute(i64)double
}
/// toString (D)Ljava/lang/String; replace 
Double_toString :: proc "c" (env: ^^kava.JNINativeInterface, double: f64) -> ^kava.ObjectHeader {
    using kava
    context = vm.ctx 
    res := fmt.aprint(double)
    defer delete(res)
    result: ^ObjectHeader = nil
    gc_alloc_string(vm, res, &result)
    return result

}
