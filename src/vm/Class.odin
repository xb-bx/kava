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
    descriptor: string,
    type: Maybe(^Class),
    access_flags: classparser.MemberAccessFlags,
    offset: i32,
    static_data: int,
    field_obj: ^ObjectHeader,

}
Method :: struct {
    name: string,
    descriptor: string, 
    access_flags: classparser.MethodAccessFlags,
    ret_type: ^Class,
    args: []^Class,
    max_locals: int,
    code: Maybe(classparser.CodeAttribute),
    parent: ^Class,
    jitted_body: [^]u8,
    exception_table: []ExceptionInfo,
    stack_base: i32,
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
    class_object: ^ObjectHeader,
    underlaying: ^Class,
    primitive: PrimitiveType,
    size: int,
    size_without_header: int,
    class_initializer_called: bool,
    is_finalizable: bool,
}
ExceptionInfo :: struct {
    start: int,
    end: int,
    exception: ^Class,
    offset: int,
}
get_class_object :: proc(vm: ^VM, class: ^Class) -> ^ObjectHeader {
    if class.class_object != nil { return class.class_object }
    context = vm.ctx
    classobj: ^ObjectHeader = nil
    append(&vm.gc.temp_roots, classobj)
    gc_alloc_object(vm, vm.classes["java/lang/Class"], &classobj)
    gc_alloc_string(vm, class.name, get_object_field_ref(classobj, "name"))
    class.class_object = classobj
    (transmute(^^Class)get_object_field_ref(classobj, "handle"))^ = class
    vm.classobj_to_class_map[classobj] = class
    return classobj
}

