package native
import kava "kava:vm"

/// initDefault ()Ljava/util/Locale; replace
initDefault :: proc "c" () -> ^kava.ObjectHeader {
    using kava
    context = vm.ctx
    if true do panic("")
    return transmute(^ObjectHeader)find_field(vm.classes["java/util/Locale"], "US").static_data
}
