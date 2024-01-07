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
/// forName0 (Ljava/lang/String;ZLjava/lang/ClassLoader;Ljava/lang/Class;)Ljava/lang/Class;
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
        class = load_class(vm, pathname).value.(^Class)
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
