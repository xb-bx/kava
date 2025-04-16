package net 
import kava "kava:vm"
import "core:sys/posix"
import "core:fmt"

is_ipv6_supported := -1

/// isIPv6Supported ()Z
InetAddressImplFactory_isIPv6Supported :: proc "c" (env: ^^kava.JNINativeInterface) -> bool {
    if is_ipv6_supported != -1 do return is_ipv6_supported == 1
    context = (env^).vm.ctx
    fd := posix.socket(posix.AF.INET6, posix.Sock.STREAM, posix.Protocol.IP); 
    defer if fd != -1 do posix.close(fd)
    if fd == -1 && posix.errno() == posix.Errno.EAFNOSUPPORT {
        is_ipv6_supported = 0
        return false
    }
    is_ipv6_supported = 1
    return true
}

