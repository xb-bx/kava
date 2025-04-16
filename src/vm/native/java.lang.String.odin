package native

import kava "kava:vm"
import "core:unicode/utf16"
import "core:strings"
import "core:fmt"


/// intern ()Ljava/lang/String;
String_intern :: proc "c" (env: ^^kava.JNINativeInterface, this: ^kava.ObjectHeader) -> ^kava.ObjectHeader {
    context = vm.ctx
    res := kava.intern(&vm.internTable, this)
    return res
}
/// <init> (Ljava/lang/String;)V replace
String_ctor :: proc "c" (env: ^^kava.JNINativeInterface, this: ^kava.ObjectHeader, other: ^kava.ObjectHeader) {
    using kava
    hashPtr := (transmute(^i32)get_object_field_ref(this, "hash"))
    valuePtr := (transmute(^^ArrayHeader)get_object_field_ref(this, "value"))
    hashPtr^ = (transmute(^i32)get_object_field_ref(other, "hash"))^
    valuePtr^ = (transmute(^^ArrayHeader)get_object_field_ref(other, "value"))^
}

/// hashCode ()I replace
String_hashCode :: proc "c" (env: ^^kava.JNINativeInterface, this: ^kava.ObjectHeader) -> i32 {
    using kava
    context = vm.ctx
    hashPtr := transmute(^i32)get_object_field_ref(this, "hash")
    value := (transmute(^^ArrayHeader)get_object_field_ref(this, "value"))^
    h: i32 = 0
    if hashPtr^ == 0 && value.length > 0 {
        val := array_to_slice(u16, value)
        for i in 0..<value.length {
            h = 31 * h + i32(val[i])
        } 
        hashPtr^ = h
    }
    return hashPtr^
}
