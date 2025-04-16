package net
import kava "kava:vm"
import "core:sys/posix"
import "core:slice"
import "core:fmt"

/// init ()V
SocketInputStream_init :: proc "c" () {}

/// socketRead0 (Ljava/io/FileDescriptor;[BIII)I
SocketInputStream_socketRead0 :: proc "c" (env: ^^kava.JNINativeInterface, this: ^kava.ObjectHeader, fdObj: ^kava.ObjectHeader, bytes: ^kava.ArrayHeader, off: i32, ln: i32, timeout: i32) -> i32 {
    context = (env^).vm.ctx
    // TODO: check null
    // TODO: check fd != -1
    fd := (transmute(^posix.FD)kava.get_object_field_ref(fdObj, "fd"))^

    if timeout != 0 {
        fds: posix.pollfd = {}
        fds.fd = fd
        fds.events = { posix.Poll_Event.OUT }
        res := posix.poll(&fds, 1, timeout)
        if res == 0 {
            kava.throw_exception_string((env^).vm, "java/net/SocketTimeoutException", "Accept timed out")
        }
    }
    array_slice := kava.array_to_slice(u8, bytes)[off:][:ln]
    res := posix.read(fd, slice.as_ptr(array_slice), len(array_slice))
    assert(res >= 0)
    return i32(res)
}

