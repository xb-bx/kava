package vm
import "kava:classparser"

PrimitiveType :: enum {
    Int,
    Char,
    Byte,
    Short,
    Float,
    Double,
    Long,
    Boolean,
    Void,
}
ClassType :: enum {
    Class = 0,
    Primitive,
    Array,
}
Field :: struct {
    name: string,
    type: ^Class,
    access_flags: classparser.MemberAccessFlags,
    offset: i32,
    static_data: int,

}
Method :: struct {
    name: string,
    descriptor: string, 
    access_flags: classparser.MethodAccessFlags,
    ret_type: ^Class,
    args: []^Class,
    locals: []^Class,
    code: Maybe(classparser.CodeAttribute),
    parent: ^Class,
    jitted_body: [^]u8,
}
Class :: struct {
    name: string,
    super_class: ^Class,
    interfaces: []^Class,
    access_flags: classparser.ClassAccessFlags,
    fields: []Field,
    instance_fields: []^Field,
    methods: []Method,
    class_file: ^classparser.ClassFile,
    class_type: ClassType,
    underlaying: ^Class,
    primitive: PrimitiveType,
    size: int,
    size_without_header: int,
    class_initializer_called: bool,
}
