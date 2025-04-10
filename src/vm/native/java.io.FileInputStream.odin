package native 

import kava "kava:vm"
import "core:os"
import "core:fmt"

import "core:io"

/// initIDs ()V 
FileInputStream_initIDs :: proc "c" (env: ^kava.JNINativeInterface, ) {
}

/// readBytes ([BII)I
FileInputStream_readBytes :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, bytes: ^kava.ArrayHeader, off: i32, len: i32) -> i32 {
    using kava
    context = vm.ctx
    fdObj := get_object_field_ref(this, "fd")^
    handle := os.Handle(cast(i32)get_object_field(fdObj, "fd"))
    data := array_to_slice(u8, bytes)[off:off+len]
    read, err := os.read(handle, data)
    assert(err == os.ERROR_NONE)
    return read == 0 ? -1 : i32(read)
}
/// available0 ()I 
FileInputStream_available0 :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader) -> i32 {
    return 0
}
/// close0 ()V
FileInputStream_close0 :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader) {
    using kava 
    context = kava.vm.ctx

    fd_obj := get_object_field_ref(this, "fd")^ 
    fd_ptr := transmute(^os.Handle)get_object_field_ref(fd_obj, "fd")
    err := os.close(fd_ptr^)
    assert(err == os.ERROR_NONE)

}
/// open0 (Ljava/lang/String;)V
FileInputStream_open0 :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, name: ^kava.ObjectHeader) {
    using kava 
    context = kava.vm.ctx
    filename := javaString_to_string(name)
    defer delete(filename)


    h, err := os.open(filename)
    assert(err == os.ERROR_NONE)
    fd_obj := get_object_field_ref(this, "fd")^ 
    fd_ptr := transmute(^os.Handle)get_object_field_ref(fd_obj, "fd")
    fd_ptr ^= h

}




