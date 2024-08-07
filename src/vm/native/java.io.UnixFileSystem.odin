package native

import kava "kava:vm"
import "core:os"
import "core:fmt"

import "core:io"

/// initIDs ()V 
UnixFileSystem_initIDs :: proc "c" () {
}
BooleanAttributes :: enum i32 {
    Exists = 0x01,
    Regular = 0x02,
    Directory = 0x04,
    Hidden = 0x08
}
/// getBooleanAttributes0 (Ljava/io/File;)I
UnixFileSystem_getBooleanAttributes0 :: proc "c" (this: ^kava.ObjectHeader, file: ^kava.ObjectHeader) -> i32 {
    using kava
    context = vm.ctx
    pathobj := kava.get_object_field_ref(file, "path")^
    path := javaString_to_string(pathobj)
    defer delete(path)
    file_info, err := os.stat(path)
    defer os.file_info_delete(file_info)
    if err == nil {
        res := BooleanAttributes.Exists
        res |= file_info.is_dir ? BooleanAttributes.Directory : BooleanAttributes.Regular
        return i32(res)
    }
    return 0
}
/// createDirectory (Ljava/io/File;)Z
UnixFileSystem_createDirectory :: proc "c" (this: ^kava.ObjectHeader, file: ^kava.ObjectHeader) -> bool {
    using kava
    context = vm.ctx
    pathobj := kava.get_object_field_ref(file, "path")^
    path := javaString_to_string(pathobj)
    defer delete(path)
    err := os.make_directory(path)
    return err == nil
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
