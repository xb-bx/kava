package net
import kava "kava:vm"
import "core:sys/posix"
import "core:slice"

/// init ()V
SocketOutputStream_init :: proc "c" () {}

/// socketWrite0 (Ljava/io/FileDescriptor;[BII)V
SocketOutputStream_socketWrite0 :: proc "c" (env: ^^kava.JNINativeInterface, this: ^kava.ObjectHeader, fdObj: ^kava.ObjectHeader, bytes: ^kava.ArrayHeader, off: i32, ln: i32) {
    context = (env^).vm.ctx
    // TODO: check null
    // TODO: check fd != -1
    fd := (transmute(^posix.FD)kava.get_object_field_ref(fdObj, "fd"))^
    bytes := kava.array_to_slice(u8, bytes)[off:][:ln]
    // TODO: check for result
    posix.write(fd, slice.as_ptr(bytes), len(bytes))
}
