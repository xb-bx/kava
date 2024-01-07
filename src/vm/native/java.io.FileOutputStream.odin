package native

import kava "kava:vm"
import "core:os"

import "core:io"
/// initIDs ()V
FileOutputStream_initIDS :: proc "c" () {}


/// writeBytes ([BIIZ)V
FileOutputStream_writeBytes :: proc "c" (this: ^kava.ObjectHeader, bytes: ^kava.ArrayHeader, off: i32, len: i32, append: bool) {
    using kava
    using os
    context = vm.ctx
    fdObj := get_object_field_ref(this, "fd")^
    fd := (cast(i32)get_object_field(fdObj, "fd"))
    data := array_to_slice(u8, bytes)[off:off+len]
    handle := Handle(fd)
    if append {
        size, size_err := file_size(handle)
        assert(size_err == ERROR_NONE)
        _, err := write_at(handle, data, size)
        assert(err == ERROR_NONE)
    }
    else {
        _, err := write(handle, data)
        assert(err == ERROR_NONE)
    }
}
