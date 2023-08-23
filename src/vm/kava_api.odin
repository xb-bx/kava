package vm
import "core:os"
import "core:fmt"
import "core:sys/unix"
import "core:intrinsics"


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
    }
}
// read (J)I
read_byte :: proc "c" (fd: os.Handle) -> i32 {
    context = vm.ctx
    b := [1]u8{}
    r, err := os.read(fd, b[:])
    if err != 0 {
        panic("")
    }
    return cast(i32)b[0]
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
