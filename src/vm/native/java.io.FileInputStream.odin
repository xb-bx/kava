package native 

import kava "kava:vm"
import "core:os"
import "core:fmt"

import "core:io"

/// initIDs ()V 
FileInputStream_initIDs :: proc "c" () {
}

/// readBytes ([BII)I
FileInputStream_readBytes :: proc "c" (this: ^kava.ObjectHeader, bytes: ^kava.ArrayHeader, off: i32, len: i32) -> i32 {
    using kava
    context = vm.ctx
    fdObj := get_object_field_ref(this, "fd")^
    when ODIN_OS == .Windows {
        handle := os.Handle(get_object_field(fdObj, "handle"))
    }
    else {
        handle := os.Handle(cast(i32)get_object_field(fdObj, "fd"))
    }
    data := array_to_slice(u8, bytes)[off:off+len]
    read, err := os.read(handle, data)
    assert(err == os.ERROR_NONE)
    return i32(read)
}
/// available0 ()I 
FileInputStream_available0 :: proc "c" (this: ^kava.ObjectHeader) -> i32 {
    return 0
}