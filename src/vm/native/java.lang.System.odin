package native

import kava "kava:vm"
import "core:unicode/utf16"
import "core:strings"
import "core:fmt"
import "core:os"
import "core:dynlib"
import "core:time"
OS_UNIX :: kava.OS_UNIX

/// currentTimeMillis ()J
System_currentTimeMillis :: proc "c" (env: ^^kava.JNINativeInterface, ) -> i64 {
    return i64(time.now()._nsec / 1000_000)
}

/// identityHashCode (Ljava/lang/Object;)I 
System_identityHashCode :: proc(env: ^^kava.JNINativeInterface, obj: ^kava.ObjectHeader) -> i32 {
    return i32(transmute(int)obj)
}

/// arraycopy (Ljava/lang/Object;ILjava/lang/Object;II)V
arraycopy :: proc "c" (env: ^^kava.JNINativeInterface, src: ^kava.ArrayHeader, src_pos: i32, dest: ^kava.ArrayHeader, desr_pos: i32, count: i32) {
    context = vm.ctx
    using kava
    if src == nil || dest == nil {
        kava.throw_NullPointerException(vm)
    }
    if src.obj.class != dest.obj.class && !is_subtype_of(src.obj.class, dest.obj.class) {
        kava.throw_NullPointerException(vm)
    }
    if src.obj.class.underlaying.class_type == ClassType.Primitive {
        switch src.obj.class.underlaying.primitive {
            case .Int, .Float:
                srcslice := array_to_slice(u32, src)[src_pos:src_pos + count]
                destslice := array_to_slice(u32, dest)[desr_pos:desr_pos + count]
                for b, i in srcslice {
                    destslice[i] = b
                }
                
            case .Char, .Short:
                srcslice := array_to_slice(u16, src)[src_pos:src_pos + count]
                destslice := array_to_slice(u16, dest)[desr_pos:desr_pos + count]
                for b, i in srcslice {
                    destslice[i] = b
                }
            case .Byte, .Boolean:
                srcslice := array_to_slice(u8, src)[src_pos:src_pos + count]
                destslice := array_to_slice(u8, dest)[desr_pos:desr_pos + count]
                for b, i in srcslice {
                    destslice[i] = b
                }
            case .Double, .Long:
                srcslice := array_to_slice(u64, src)[src_pos:src_pos + count]
                destslice := array_to_slice(u64, dest)[desr_pos:desr_pos + count]
                for b, i in srcslice {
                    destslice[i] = b
                }
            case .Void:
                panic("")
        }

    }
    else {
        srcslice := array_to_slice(u64, src)[src_pos:src_pos + count]
        destslice := array_to_slice(u64, dest)[desr_pos:desr_pos + count]
        for b, i in srcslice {
            destslice[i] = b
        }
    }

}

/// getProperty (Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String; replace
System_getProperty2 :: proc "c" (env: ^^kava.JNINativeInterface, str: ^kava.ObjectHeader, def: ^kava.ObjectHeader) -> ^kava.ObjectHeader {
    res := System_getProperty(env, str)
    if res == nil do return def
    return res
}
/// getProperty (Ljava/lang/String;)Ljava/lang/String; replace
System_getProperty :: proc "c" (env: ^^kava.JNINativeInterface, str: ^kava.ObjectHeader) -> ^kava.ObjectHeader {
    using kava
    context = vm.ctx
    prop := javaString_to_string(str)
    defer delete(prop)
    if prop == "file.encoding" {
        str: ^kava.ObjectHeader = nil 
        kava.gc_alloc_string(vm, "UTF-8", &str)
        return str
    } else if prop == "sun.nio.cs.bugLevel" {
        str: ^kava.ObjectHeader = nil 
        kava.gc_alloc_string(vm, "1.8", &str)
        return str
    } else if prop == "line.separator" {
        str: ^kava.ObjectHeader = nil 
        kava.gc_alloc_string(vm, "\n", &str)
        return str
    } else if prop == "sun.reflect.noCaches" {
        str: ^kava.ObjectHeader = nil 
        kava.gc_alloc_string(vm, "true", &str)
        return str
    } else if prop == "sun.io.useCanonCaches" {
        str: ^kava.ObjectHeader = nil 
        kava.gc_alloc_string(vm, "true", &str)
        return str
    } else if prop == "sun.io.useCanonPrefixCache" {
        str: ^kava.ObjectHeader = nil 
        kava.gc_alloc_string(vm, "true", &str)
        return str
    } else if prop == "file.separator" {
        str: ^kava.ObjectHeader = nil 
        kava.gc_alloc_string(vm, "/", &str)
        return str
    } else if prop == "path.separator" {
        str: ^kava.ObjectHeader = nil 
        kava.gc_alloc_string(vm, ":", &str)
        return str
    } else if prop == "java.home" {
        str: ^kava.ObjectHeader = nil 
        kava.gc_alloc_string(vm, "", &str)
        return str
    } else if prop == "java.ext.dirs" {
        str: ^kava.ObjectHeader = nil 
        kava.gc_alloc_string(vm, ".", &str)
        return str
    } else if prop == "java.library.path" {
        str: ^kava.ObjectHeader = nil
        ld_lib_path := os.get_env("LD_LIBRARY_PATH")
        fmt.println("library path", ld_lib_path)
        defer delete(ld_lib_path)
        kava.gc_alloc_string(vm, ld_lib_path, &str)
        return str
    } else if prop == "user.dir" {
        str: ^kava.ObjectHeader = nil 
        home_dir := os.get_env("HOME")
        kava.gc_alloc_string(vm, home_dir, &str)
        delete(home_dir)
        return str
    } else if prop == "user.language.format" {
        return nil
    } else if prop == "user.script.format" {
        return nil
    } else if prop == "user.country.format" {
        return nil
    } else if prop == "user.variant.format" {
        return nil
    } else {
        fmt.println(prop)
        //panic("exception")
        return nil
    }
    return nil
//     return nil
}
when OS_UNIX {
    /// registerNatives ()V
    System_registerNatives :: proc "c" (env: ^^kava.JNINativeInterface, ) {
        using kava
        context = vm.ctx
        system := vm.classes["java/lang/System"]
        fdclass := load_class(vm, "java/io/FileDescriptor").value.(^Class)  
        fdclass.class_initializer_called = true
        ctor := transmute(proc "c" (env: ^^JNINativeInterface, fd: ^ObjectHeader, fdint: i32))find_method(fdclass, "<init>", "(I)V").jitted_body
        infld := transmute(^^ObjectHeader)&find_field(fdclass, "in").static_data
        outfld := transmute(^^ObjectHeader)&find_field(fdclass, "out").static_data
        errfld := transmute(^^ObjectHeader)&find_field(fdclass, "err").static_data
        gc_alloc_object(vm, fdclass, infld)
        ctor(env, infld^, 0)
        gc_alloc_object(vm, fdclass, outfld)
        ctor(env, outfld^, 1)
        gc_alloc_object(vm, fdclass, errfld)
        ctor(env, errfld^, 2)
        fileOutputStream := load_class(vm, "java/io/FileOutputStream").value.(^Class)
        printStream := load_class(vm, "java/io/PrintStream").value.(^Class)
        fileOutputStream_init := (transmute(proc "c" (env: ^^JNINativeInterface, this: ^ObjectHeader, fd: ^ObjectHeader))find_method(fileOutputStream, "<init>", "(Ljava/io/FileDescriptor;)V").jitted_body)
        printStream_init := (transmute(proc "c" (env: ^^JNINativeInterface, this: ^ObjectHeader, stream: ^ObjectHeader))find_method(printStream, "<init>", "(Ljava/io/OutputStream;)V").jitted_body)

        out_printStream_ref := transmute(^^ObjectHeader)&find_field(system, "out").static_data
        gc_alloc_object(vm, printStream, out_printStream_ref)

        out_file_stream: ^ObjectHeader = nil
        gc_alloc_object(vm, fileOutputStream, &out_file_stream)
        fileOutputStream_init(env, out_file_stream, outfld^)
        
        printStream_init(env, out_printStream_ref^, out_file_stream)


        err_printStream_ref := transmute(^^ObjectHeader)&find_field(system, "err").static_data
        gc_alloc_object(vm, printStream, err_printStream_ref)

        err_file_stream: ^ObjectHeader = nil
        gc_alloc_object(vm, fileOutputStream, &err_file_stream)
        fileOutputStream_init(env, err_file_stream, errfld^)
        
        printStream_init(env, err_printStream_ref^, err_file_stream)


        fileInputStream := load_class(vm, "java/io/FileInputStream").value.(^Class)
        fileInputStream_init := (transmute(proc "c" (env: ^^JNINativeInterface, this: ^ObjectHeader, fd: ^ObjectHeader))find_method(fileInputStream, "<init>", "(Ljava/io/FileDescriptor;)V").jitted_body)
        in_ref := transmute(^^ObjectHeader)&find_field(system, "in").static_data
        gc_alloc_object(vm, fileInputStream, in_ref)
        fileInputStream_init(env, in_ref^, infld^);

    }
}
/// mapLibraryName (Ljava/lang/String;)Ljava/lang/String; 
System_mapLibraryName :: proc "c" (env: ^^kava.JNINativeInterface, str: ^kava.ObjectHeader) -> ^kava.ObjectHeader {
    context = vm.ctx
    s := kava.javaString_to_string(str)
    defer delete(s)
    lib := fmt.aprintf("lib%s.so", s)
    defer delete(lib)
    res: ^kava.ObjectHeader
    kava.gc_alloc_string(vm, lib, &res)
    return res
}
/// loadLibrary (Ljava/lang/String;)V replace
System_loadLibrary :: proc "c" (env: ^^kava.JNINativeInterface, str: ^kava.ObjectHeader) {
    context = vm.ctx
    s := kava.javaString_to_string(str)
    defer delete(s)
    lib := fmt.aprintf("lib%s.so", s)
    defer delete(lib)
    if !kava.vm_load_library(vm, lib) do panic(lib)
}

/// <clinit> ()V replace
System_clinit :: proc "c" (env: ^^kava.JNINativeInterface, )  { System_registerNatives(env) }
