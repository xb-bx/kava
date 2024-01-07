package native

import kava "kava:vm"
import "core:unicode/utf16"
import "core:strings"
import "core:fmt"

/// defaultCharset ()Ljava/nio/charset/Charset; replace 
Charset_defaultCharset :: proc "c" () -> ^kava.ObjectHeader {
    using kava
    context = vm.ctx
    charsetClass := vm.classes["java/nio/charset/Charset"]
    
    utf8Class := load_class(vm, "sun/nio/cs/UTF_8").value.(^Class)
    defaultCharsetFld := find_field(charsetClass, "defaultCharset")
    if defaultCharsetFld.static_data != 0 {
        return transmute(^ObjectHeader)defaultCharsetFld.static_data 
    }
    default := transmute(^^ObjectHeader)&defaultCharsetFld.static_data
    gc_alloc_object(vm, utf8Class, default)
    init := transmute(proc "c" (thisobj: ^ObjectHeader))(find_method(utf8Class, "<init>", "()V").jitted_body)
    name: ^ObjectHeader = nil
    gc_alloc_string(vm, "UTF-8", &name)
    init(default^)
    (transmute(proc "c" (name: ^ObjectHeader, charset: ^ObjectHeader))(find_method(charsetClass, "cache", "(Ljava/lang/String;Ljava/nio/charset/Charset;)V").jitted_body))(name, default^)
    return default^
}


