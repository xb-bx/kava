package native

import kava "kava:vm"
import "core:os"
import "core:fmt"

import "core:io"

/// initIDs ()V 
UnixFileSystem_initIDs :: proc "c" () {
}
/// getLength (Ljava/io/File;)J
UnixFileSystem_getLength :: proc "c" (this: ^kava.ObjectHeader, file: ^kava.ObjectHeader) -> i64 {
    using kava
    context = vm.ctx
    filename_obj := kava.get_object_field_ref(file, "path")^
    filename := javaString_to_string(filename_obj)
    defer delete(filename)

    h, err := os.open(filename)
    defer if err == os.ERROR_NONE do os.close(h)
    if err != os.ERROR_NONE do return 0

    fstat, fstat_err := os.fstat(h)
    defer os.file_info_delete(fstat)
    if fstat_err != os.ERROR_NONE do return 0
    
    return fstat.size

}
