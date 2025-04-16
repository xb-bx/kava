package net 
import kava "kava:vm"
import "core:sys/posix"
import "core:fmt"
import "core:mem"
import "core:sys/linux"

/// initProto ()V
PlainSocketImpl_initProto :: proc "c" (env: ^^kava.JNINativeInterface) {
}
/// socketCreate (Z)V
PlainSocketImpl_socketCreate :: proc "c" (env: ^^kava.JNINativeInterface, this: ^kava.ObjectHeader, stream: bool) {
    context = (env^).vm.ctx
    sock := stream ? posix.Sock.STREAM : posix.Sock.DGRAM
    domain := InetAddressImplFactory_isIPv6Supported(env) ? posix.AF.INET6 : posix.AF.INET
    fdObj := kava.get_object_field_ref(this, "fd")^
    assert(fdObj != nil)
    fd := posix.socket(domain, sock, cast(posix.Protocol)0)
    assert(fd != -1)
    server_sock := kava.get_object_field_ref(this, "serverSocket")^
    if server_sock != nil {
        flags := posix.fcntl(fd, posix.FCNTL_Cmd.GETFL)
        flags |= i32(posix.O_Flag_Bits.NONBLOCK)
        posix.fcntl(fd, posix.FCNTL_Cmd.SETFL, flags)
        arg: i32 = 1
        res := posix.setsockopt(fd, posix.SOL_SOCKET, posix.Sock_Option.REUSEADDR, &arg, size_of(arg))
        assert(res == .OK)
    }
    fdfd := transmute(^i32)kava.get_object_field_ref(fdObj, "fd")
    fdfd ^= i32(fd)
}
IPv4 :: 1
IPv6 :: 2
inetAddress_toSockaddr :: proc (vm: ^kava.VM, ia: ^kava.ObjectHeader, port: i32, addr: ^posix.sockaddr) -> u32 { 
    holder := kava.get_object_field_ref(ia, "holder")^
    family := (transmute(^i32)(kava.get_object_field_ref(holder, "family")))^
    if InetAddressImplFactory_isIPv6Supported(&vm.jni_env) { 
        addr6 := transmute(^posix.sockaddr_in6)addr
        mem.set(addr6, 0, size_of(^posix.sockaddr_in6))
        caddr := [16]u8 {}
        address: i32 = 0
        if family == IPv4 {
            address := (transmute(^i32)(kava.get_object_field_ref(holder, "address")))^
            caddr[10] = 0xff
            caddr[11] = 0xff
            caddr[12] = u8(((address >> 24) & 0xff))
            caddr[13] = u8(((address >> 16) & 0xff))
            caddr[14] = u8(((address >> 8) & 0xff))
            caddr[15] = u8((address & 0xff))
        } else {
            holder6 := kava.get_object_field_ref(ia, "holder6")^
            address := (transmute(^^kava.ArrayHeader)(kava.get_object_field_ref(holder, "ipaddress")))
            if address^ == nil {
                kava.gc_alloc_array(vm, vm.classes["[B"], 16, address)
            }
            address_bytes := kava.array_to_slice(u8, address^)
            copy_slice(caddr[:], address_bytes)
        }
        addr6.sin6_port = u16be(port)
        addr6.sin6_addr.s6_addr = caddr
        addr6.sin6_family = posix.sa_family_t.INET6
        return size_of(posix.sockaddr_in6)
    } else {
        if family == IPv6 {
            panic("oops")
        }
        addr4 := transmute(^posix.sockaddr_in)addr
        mem.set(addr4, 0, size_of(^posix.sockaddr_in))
        address := (transmute(^i32)(kava.get_object_field_ref(holder, "address")))^
        addr4.sin_port = u16be(port)
        addr4.sin_addr.s_addr = u32be(address)
        addr4.sin_family =  posix.sa_family_t.INET
        return size_of(posix.sockaddr_in);
    }
}

/// socketBind (Ljava/net/InetAddress;I)V
PlainSocketImpl_socketBind :: proc "c" (env: ^^kava.JNINativeInterface, this: ^kava.ObjectHeader, iaObj: ^kava.ObjectHeader, localPort: i32) {
    context = (env^).vm.ctx
    fdObj := kava.get_object_field_ref(this, "fd")^
    assert(fdObj != nil)
    fd := (transmute(^posix.FD)kava.get_object_field_ref(fdObj, "fd"))^
    addr_raw, _ := mem.alloc(256)
    addr: ^posix.sockaddr = transmute(^posix.sockaddr) addr_raw
    addr_len := inetAddress_toSockaddr((env^).vm, iaObj, localPort, addr)
    res := posix.bind(fd, addr, posix.socklen_t(addr_len))
    assert(res == .OK)
}

/// socketListen (I)V
PlainSocketImpl_socketListen :: proc "c" (env: ^^kava.JNINativeInterface, this: ^kava.ObjectHeader, count: i32) {
    context = (env^).vm.ctx
    fdObj := kava.get_object_field_ref(this, "fd")^
    assert(fdObj != nil)
    fd := (transmute(^posix.FD)kava.get_object_field_ref(fdObj, "fd"))^
    res := posix.listen(fd, count) 
    assert(res == .OK)
}
/// socketClose0 (Z)V
PlainSocketImpl_socketClose0 :: proc "c" (env: ^^kava.JNINativeInterface, this: ^kava.ObjectHeader, deferedClose: bool) {
    context = (env^).vm.ctx    
    fdObj := kava.get_object_field_ref(this, "fd")^
    assert(fdObj != nil)
    fdptr := (transmute(^posix.FD)kava.get_object_field_ref(fdObj, "fd"))
    posix.close(fdptr^)
    fdptr ^= -1
}
sockaddr_to_InetAddress :: proc "c" (env: ^^kava.JNINativeInterface, addr: ^posix.sockaddr, port: ^i32) -> ^kava.ObjectHeader {
    using kava
    is_ipv4mapped :: proc(caddr: []u8) -> bool {
        for i in 0..<10 {
            if caddr[i] != 0x00 {
                return false
            }
        }
        if ((caddr[10] & 0xff) == 0xff) && ((caddr[11] & 0xff) == 0xff) {
            return true
        }
        return true
    }
    ipv4mapped_to_ipv4 :: proc(caddr: []u8) -> i32 {
        return (transmute(^i32)(&caddr[12]))^
    }
    context = (env^).vm.ctx
    if addr.sa_family == posix.sa_family_t.INET6 {
        addr6 := transmute(^posix.sockaddr_in6)addr
        port ^= i32(addr6.sin6_port)
        if is_ipv4mapped(addr6.sin6_addr.s6_addr[:]) {
            class := load_class(vm, "java/net/Inet4Address").value.(^Class)
            iaObj: ^ObjectHeader = nil
            gc_alloc_object(vm, class, &iaObj)
            ctor := transmute(proc "c" (env: ^^JNINativeInterface, this: ^ObjectHeader))(find_method(class, "<init>", "()V"))
            ctor(env, iaObj)
            address := ipv4mapped_to_ipv4(addr6.sin6_addr.s6_addr[:])
            holder := get_object_field_ref(iaObj, "holder")^
            addressptr := transmute(^i32)(get_object_field_ref(holder, "address"))
            addressptr ^= address
            familyptr := transmute(^i32)(get_object_field_ref(holder, "family"))
            familyptr ^= IPv4
            return iaObj
        } else {
            panic("oops") 
        }     
    } else {
        addr4 := transmute(^posix.sockaddr_in)addr
        port ^= i32(addr4.sin_port)
        class := load_class(vm, "java/net/Inet4Address").value.(^Class)
        iaObj: ^ObjectHeader = nil
        gc_alloc_object(vm, class, &iaObj)
        ctor := transmute(proc "c" (env: ^^JNINativeInterface, this: ^ObjectHeader))(find_method(class, "<init>", "()V").jitted_body)
        ctor(env, iaObj)
        address := (addr4.sin_addr.s_addr)
        holder := get_object_field_ref(iaObj, "holder")^
        addressptr := transmute(^i32)(get_object_field_ref(holder, "address"))
        addressptr ^= i32(address)
        familyptr := transmute(^i32)(get_object_field_ref(holder, "family"))
        familyptr ^= IPv4
        return iaObj
    }
}
/// socketAccept (Ljava/net/SocketImpl;)V
PlainSocketImpl_socketAccept :: proc "c" (env: ^^kava.JNINativeInterface, this: ^kava.ObjectHeader, socket: ^kava.ObjectHeader) {
    context = (env^).vm.ctx
    fdObj := kava.get_object_field_ref(this, "fd")^
    assert(fdObj != nil)
    fd := (transmute(^posix.FD)kava.get_object_field_ref(fdObj, "fd"))^
    timeout := (transmute(^i32)(kava.get_object_field_ref(this, "timeout")))^
    if timeout <= 0 do timeout = -1
    addr_raw, _ := mem.alloc(256)
    addr: ^posix.sockaddr = transmute(^posix.sockaddr) addr_raw
    ln :posix.socklen_t= 0
    fds: posix.pollfd = {}
    fds.fd = fd
    fds.events = { posix.Poll_Event.IN }
    res := posix.poll(&fds, 1, timeout)
    if res == 0 {
        kava.throw_exception_string((env^).vm, "java/net/SocketTimeoutException", "Accept timed out")
    }
    newfd := posix.accept(fd, addr, &ln)
    port: i32 = 0
    iaobj := sockaddr_to_InetAddress(env, addr, &port)
    assert(newfd >= 0)

    sockfdObj := kava.get_object_field_ref(socket, "fd")^
    assert(sockfdObj != nil)
    fdptr := (transmute(^posix.FD)kava.get_object_field_ref(sockfdObj, "fd"))
    fdptr ^= newfd
    addrptr := kava.get_object_field_ref(socket, "address")
    addrptr ^= iaobj
    portptr := (transmute(^i32)kava.get_object_field_ref(socket, "port"))
    portptr ^= i32(port)
    localportptr := (transmute(^i32)kava.get_object_field_ref(socket, "localport"))
    localport := (transmute(^i32)kava.get_object_field_ref(this, "localport"))^
    localportptr ^= localport
}
FIONREAD :: 0x541B
/// socketAvailable ()I
PlainSocketImpl_socketAvailable :: proc "c" (env: ^^kava.JNINativeInterface, this: ^kava.ObjectHeader) -> i32 {
    context = (env^).vm.ctx
    fdObj := kava.get_object_field_ref(this, "fd")^
    assert(fdObj != nil)
    fd := (transmute(^linux.Fd)kava.get_object_field_ref(fdObj, "fd"))^
    bytes: i32 = 0
    res := linux.ioctl(fd, FIONREAD, uintptr(&bytes))
    assert(int(res) != -1)
    return bytes
}
