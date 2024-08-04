package native

import kava "kava:vm"
import "core:unicode/utf16"
import "core:strings"
import "core:fmt"


/// intern ()Ljava/lang/String;
String_intern :: proc "c" (this: ^kava.ObjectHeader) -> ^kava.ObjectHeader {
    context = vm.ctx
    kava.intern(&vm.internTable, this)
    return this
}
