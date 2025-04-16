package native

import kava "kava:vm"

/// <clinit> ()V replace
Bits_clinit :: proc "c" (env: ^^kava.JNINativeInterface, ) {
    using kava
    context = vm.ctx
    bitsClass := vm.classes["java/nio/Bits"]
    byteOrderClass := vm.classes["java/nio/ByteOrder"] 
    jit_ensure_clinit_called_body(vm, find_method(byteOrderClass, "<clinit>", "()V"))
    (transmute(^^ObjectHeader)&find_field(bitsClass, "byteOrder").static_data)^ = transmute(^ObjectHeader)find_field(byteOrderClass, "LITTLE_ENDIAN").static_data
    bitsClass.class_initializer_called = true
}

