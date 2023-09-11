package vm
import "core:os"
import "core:fmt"
import "core:sys/unix"
import "core:intrinsics"
import "core:math/rand"
import "core:math"

/// randomDouble ()D
random_double :: proc "c" () -> f64 { 
    context = vm.ctx
    return rand.float64_range(0.0, math.nextafter_f64(1.0, 2.0))

} 

/// write (JI)V
write_byte :: proc "c" (fd: os.Handle, b: i32) { 
    context = vm.ctx
    os.write_byte(fd, cast(u8)b) 
} 


/// getStdout ()Ljava/io/FileOutputStream;
getStdout :: proc "c" () -> ^ObjectHeader {
    context = vm.ctx
    fs: ^ObjectHeader = nil
    gc_alloc_object(vm, vm.classes["java/io/FileOutputStream"], &fs)
    set_object_field(fs, "fd", cast(int)os.stdout)
    return fs
} 
FIONREAD :: 21531
// getAvailableBytes (J)I
getAvailableBytes :: proc "c" (fd: os.Handle) -> i32 {
    context = vm.ctx 
    when ODIN_OS == .Linux {
        available: i32 = 0
        res := cast(int)intrinsics.syscall(unix.SYS_ioctl, cast(uintptr)fd, FIONREAD, transmute(uintptr)&available)
        if res < 0 {
            panic("oopsie")
        }
        return available
    } else {
        throw_NotImplementedException(vm, "Cannot get available bytes on windows rn")
        return 0
    }
}

// read (J)I
read_byte :: proc "c" (fd: os.Handle) -> i32 {
    context = vm.ctx
    b := [1]u8{}
    r, err := os.read(os.stdin, b[:])
    if r <= 0 {
        panic("")
    }
    return cast(i32)b[0]
}
/// read (J[BII)I 
read_bytes :: proc "c" (fd: os.Handle, bytes: ^ArrayHeader, off: i32, len: i32) -> i32 {
    context = vm.ctx
    slice := array_to_slice(u8, bytes)[off:off+len]
    res, err := os.read(fd, slice)
    if err != 0 {
        panic("")
    }
    return cast(i32)res
}
// getStdin ()Ljava/io/FileInputStream;
getStdin :: proc "c" () -> ^ObjectHeader {
    context = vm.ctx
    fs: ^ObjectHeader = nil
    gc_alloc_object(vm, vm.classes["java/io/FileInputStream"], &fs)
    set_object_field(fs, "fd", cast(int)os.stdin)
    return fs
}
/// flush (J)V
flush :: proc "c" (fd: os.Handle) { 
    when ODIN_OS == .Windows {
        context = vm.ctx
        os.flush(fd)
    }
}

// objectToString (Ljava/lang/Object;)Ljava/lang/String;
objectToString :: proc "c" (obj: ^ObjectHeader) -> ^ObjectHeader {
    str: ^ObjectHeader = nil
    gc_alloc_string(vm, obj.class.name, &str)
    return str
}
// objectHashCode (Ljava/lang/Object;)I
objectHashCode :: proc "c" (obj: ^ObjectHeader) -> i32 {
    return i32(transmute(uintptr)(obj))
}

