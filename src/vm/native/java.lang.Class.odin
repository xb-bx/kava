package native
import kava "kava:vm"
import "core:strings"
import "core:fmt"

/// registerNatives ()V
Class_registerNatives :: proc "c" () {}

/// desiredAssertionStatus0 (Ljava/lang/Class;)Z
Class_desiredAssertionStatus0 :: proc "c" () -> i32 {
    return 0
}


/// getClassLoader0 ()Ljava/lang/ClassLoader;
Class_getClassLoader0 :: proc "c" () -> ^kava.ObjectHeader { return nil }

/// isArray ()Z
Class_isArray :: proc "c" (this: ^kava.ObjectHeader) -> bool {
    using kava
    context = vm.ctx
    class := transmute(^Class)get_object_field(this, "handle")
    return class.class_type == ClassType.Array
}
/// getComponentType ()Ljava/lang/Class;
Class_getComponentType :: proc "c" (this: ^kava.ObjectHeader) -> ^kava.ObjectHeader {
    using kava
    context = vm.ctx
    class := transmute(^Class)get_object_field(this, "handle")
    if class.class_type == ClassType.Array {
        return get_class_object(vm, class.underlaying)
    } else {
        return nil
    }
}

/// getPrimitiveClass (Ljava/lang/String;)Ljava/lang/Class;
Class_getPrimitiveClass :: proc "c" (str: ^kava.ObjectHeader) -> ^kava.ObjectHeader {
    using kava
    context = vm.ctx
    str := javaString_to_string(str)
    defer delete(str)
    class := vm.classes[str]
    if class.class_type != ClassType.Primitive {
        return nil
    }
    return get_class_object(vm, class) 
}
/// forName0 (Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;
Class_forName :: proc "c" (name: ^kava.ObjectHeader, initialize: bool, loader: ^kava.ObjectHeader, callerClass: ^kava.ObjectHeader) -> ^kava.ObjectHeader {
    using kava
    context = vm.ctx
    namestr := javaString_to_string(name)
    defer delete(namestr)
    pathname, was_alloc := strings.replace_all(namestr, ".", "/");
    class : ^Class = nil
    class = vm.classes[pathname]
    if class != nil {
        delete(pathname)
        return get_class_object(vm, class)
    }
    else {
        classres := load_class(vm, pathname)
        if classres.is_err {
            throw_exception(vm, "java/lang/ClassNotFoundException", pathname) 
        }
        class := classres.value.(^Class)
        return get_class_object(vm, class)
    }
}
/// newInstance ()Ljava/lang/Object; replace
Class_newInstance :: proc "c" (this: ^kava.ObjectHeader) -> ^kava.ObjectHeader {
    using kava
    context = vm.ctx
    class := vm.classes[javaString_to_string(get_object_field_ref(this, "name")^)]
    initializer := find_method(class, "<clinit>", "()V")
    if initializer != nil {
        jit_ensure_clinit_called_body(vm, class, initializer)
    }
    newobj: ^ObjectHeader = nil
    gc_alloc_object(vm, class, &newobj)
    (transmute(proc "c"(obj: ^ObjectHeader))find_method(class, "<init>", "()V").jitted_body)(newobj)
    return newobj
    
}
/// getDeclaredFields0 (Z)[Ljava/lang/reflect/Field;
Class_getDeclaredFields0 :: proc "c" (this: ^kava.ObjectHeader, publicOnly: bool) -> ^kava.ArrayHeader {
    using kava
    context = vm.ctx
    field_class := vm.classes["java/lang/reflect/Field"]
    field_ctor := kava.find_method(field_class, "<init>", "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;IILjava/lang/String;[B)V")
    ctor_proc := transmute(proc "c" (this: ^kava.ObjectHeader, class: ^kava.ObjectHeader, name: ^kava.ObjectHeader, type: ^kava.ObjectHeader, modifiers: i32, slot: i32, signature: ^kava.ObjectHeader, anotations: ^kava.ArrayHeader))(field_ctor.jitted_body)
    class := vm.classes[javaString_to_string(get_object_field_ref(this, "name")^)]
    fields := make([dynamic]^kava.ObjectHeader)
    defer delete(fields)
    for &field in class.fields {
        if field.field_obj != nil {
            append(&fields, field.field_obj)
        } else {
            gc_alloc_object(vm, field_class, &field.field_obj)
            name_str: ^ObjectHeader = nil
            gc_alloc_string(vm, field.name, &name_str)
            name_str = intern(&vm.internTable, name_str)
            field_type: ^Class = nil 
            if field.type != nil {
                field_type = field.type.(^Class)
            } else {
                field_type = load_class(vm, field.descriptor).value.(^Class)
            }
            ctor_proc(field.field_obj, this, name_str, get_class_object(vm, field_type), i32(field.access_flags), 0, nil, nil)
            append(&fields, field.field_obj)
        }
    }
    fields_array: ^kava.ArrayHeader = nil
    gc_alloc_array(vm, vm.classes["java/lang/reflect/Field"], len(fields), &fields_array)
    fields_slice := kava.array_to_slice(^ObjectHeader, fields_array)
    for fld, i in fields {
        fields_slice[i] = fld 
    }
    return fields_array
}
