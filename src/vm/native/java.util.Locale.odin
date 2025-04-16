package native
import kava "kava:vm"

/// initDefault ()Ljava/util/Locale; replace
initDefault :: proc "c" (env: ^^kava.JNINativeInterface, ) -> ^kava.ObjectHeader {
    using kava
    context = vm.ctx
    return transmute(^ObjectHeader)find_field(vm.classes["java/util/Locale"], "US").static_data
}
