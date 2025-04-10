package native

import kava "kava:vm"
import "core:os"
import "core:fmt"
import "core:path/filepath"

import "core:io"

/// initIDs ()V 
UnixFileSystem_initIDs :: proc "c" (env: ^kava.JNINativeInterface, ) {
}
BooleanAttributes :: enum i32 {
    Exists = 0x01,
    Regular = 0x02,
    Directory = 0x04,
    Hidden = 0x08
}
/// canonicalize0 (Ljava/lang/String;)Ljava/lang/String;
UnixFileSystem_canonicalize0 :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, path: ^kava.ObjectHeader) -> ^kava.ObjectHeader {
    using kava
    context = vm.ctx
    path := javaString_to_string(path)
    defer delete(path)
    res := filepath.clean(path)
    defer delete(res)
    result: ^kava.ObjectHeader = nil
    gc_alloc_string(vm, res, &result)
    return result
}
/// list (Ljava/io/File;)[Ljava/lang/String;
UnixFileSystem_list :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, file: ^kava.ObjectHeader) -> ^kava.ArrayHeader {
    using kava
    context = vm.ctx
    pathobj := kava.get_object_field_ref(file, "path")^
    path := javaString_to_string(pathobj)
    defer delete(path)
    file_info, err := os.stat(path)
    defer os.file_info_delete(file_info)
    if err == nil {
        if !file_info.is_dir do return nil
        handle, openerr := os.open(path)
        defer os.close(handle)
        if openerr != nil do return nil
        finfos, read_err := os.read_dir(handle, -1)
        defer os.file_info_slice_delete(finfos)
        if read_err != nil do return nil
        result: ^ArrayHeader = nil
        i := append(&vm.gc.temp_roots, &result.obj)

        gc_alloc_array(vm, vm.classes["java/lang/String"], len(finfos), &result)
        result_slice := array_to_slice(^ObjectHeader, result)
        
        for finfo,i in finfos {
            gc_alloc_string(vm, finfo.name, &result_slice[i])
        }
        ordered_remove(&vm.gc.temp_roots, i)
        return result
    }
    return nil
}
/// getBooleanAttributes0 (Ljava/io/File;)I
UnixFileSystem_getBooleanAttributes0 :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, file: ^kava.ObjectHeader) -> i32 {
    using kava
    context = vm.ctx
    pathobj := kava.get_object_field_ref(file, "path")^
    path := javaString_to_string(pathobj)
    defer delete(path)
    fmt.println("getBoolAttributes: ", path)
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
UnixFileSystem_createDirectory :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, file: ^kava.ObjectHeader) -> bool {
    using kava
    context = vm.ctx
    pathobj := kava.get_object_field_ref(file, "path")^
    path := javaString_to_string(pathobj)
    defer delete(path)
    err := os.make_directory(path)
    return err == nil
}

/// getLength (Ljava/io/File;)J
UnixFileSystem_getLength :: proc "c" (env: ^kava.JNINativeInterface, this: ^kava.ObjectHeader, file: ^kava.ObjectHeader) -> i64 {
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
