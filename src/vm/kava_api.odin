package vm
import "core:os"
import "core:fmt"


/// write (JI)V
write_byte :: proc "c" (fd: os.Handle, b: i32) { 
    context = vm.ctx
    os.write_byte(fd, cast(u8)b) 
} 


/// getStdout ()Ljava/io/FileOutputStream;
getStdout :: proc "c" () -> ^ObjectHeader {
    context = vm.ctx
    fs := gc_alloc_object(vm, vm.classes["java/io/FileOutputStream"])
    set_object_field(fs, "fd", cast(int)os.stdout)
    return fs
} 
/// flush (J)V
flush :: proc "c" (fd: os.Handle) { 
    when ODIN_OS == .Windows {
        context = vm.ctx
        os.flush(fd)
    }
}
