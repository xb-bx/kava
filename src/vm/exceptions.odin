package vm
import "core:fmt"
import "core:slice"
import "core:strings"
throw_NullPointerException :: proc(vm: ^VM) {
    throw_exception(vm, "java/lang/NullPointerException")
}
throw_NotImplementedException :: proc(vm: ^VM, msg: string) {
    throw_exception(vm, "java/lang/NotImplementedException", msg)
//     nimpl: ^ObjectHeader = nil
//     msgstring: ^ObjectHeader = nil
//     gc_alloc_object(vm, vm.classes["java/lang/NotImplementedException"], &nimpl) 
//     gc_alloc_string(vm, msg, &msgstring)
//     set_object_field(nimpl, "message", transmute(int)msgstring)
//     rbp := 0
//     target := throw(vm, nimpl, &rbp)
//     asm(^ObjectHeader) #side_effects #intel { "mov rdi, rax", ":rax" }(nimpl)
//     asm(int) #side_effects #intel { "mov rbp, rax", ":rax" }(rbp)
//     asm(int) #side_effects #intel { "jmp rax", ":rax" }(target)
}
throw_exception :: proc { throw_exception_strobj, throw_exception_string }
throw_exception_strobj :: proc "c" (vm: ^VM, exception_name: string, message: ^ObjectHeader = nil) {
    context = vm.ctx
    nimpl: ^ObjectHeader = nil
    exc := load_class(vm, exception_name)
    gc_alloc_object(vm, exc.value.(^Class), &nimpl) 
    set_object_field(nimpl, "detailMessage", transmute(int)message)
    rbp := 0
    size := 0
    target := throw_impl(vm, nimpl, &rbp, &size)
    asm(^ObjectHeader) #side_effects #intel { "mov rdi, rax", ":rax" }(nimpl)
    asm(int) #side_effects #intel { "mov r10, rax", ":rax" }(target)
    asm(int) #side_effects #intel { "mov r11, rax", ":rax" }(size)
    asm(int) #side_effects #intel { "mov rbp, rax", ":rax" }(rbp)
    asm(int) #side_effects #intel { "mov rsp, rbp", ":rax" }(0)
    asm(int) #side_effects #intel { "sub rsp, r11", ":rax" }(0)
    asm(int) #side_effects #intel { "jmp r10", ":rax" }(0)

}
throw_exception_string :: proc "c" (vm: ^VM, exception_name: string, message: string ) {
    messageobj : ^ObjectHeader = nil 
    context = vm.ctx
    gc_alloc_string(vm, message, &messageobj)
    throw_exception(vm, exception_name, messageobj)
} 
throw_impl :: proc "c" (vm: ^VM, exc: ^ObjectHeader, old_rbp: ^int, size: ^int) -> int {
    context = vm.ctx
    i := len(stack_trace) - 1
    items_to_remove := 0
    for i >= 0 {
        entry := stack_trace[i]
        table := entry.method.exception_table
        for exception in table {
        if exception.exception == exc.class || is_subtype_of(exc.class, exception.exception) {
                if entry.pc >= exception.start && entry.pc <= exception.end {
                    if items_to_remove > 0 {
                        start := len(stack_trace) - items_to_remove
                        remove_range(stack_trace, start, start + items_to_remove)
                    }
                    old_rbp^ = entry.rbp
                    size^ = entry.size
                    return transmute(int)entry.method.jitted_body + exception.offset 
                }
            }
        }
        items_to_remove += 1
        i -= 1
    }
        
// 
    toString := transmute(proc "c" (^^JNINativeInterface, ^ObjectHeader) -> ^ObjectHeader)(jit_resolve_virtual(vm, exc, find_method(vm.classes["java/lang/Object"], "toString", "()Ljava/lang/String;"), nil)^)    
//     assert(toString != nil)
    
    str := toString(&vm.jni_env, exc)
    msg := javaString_to_string(str)
    fmt.println(msg)
    fmt.println(get_detail(exc))
    fmt.println(exc.class.name)
    print_stack_trace()
    panic("")
}
get_detail :: proc (exc: ^ObjectHeader) -> string {
    msg := get_object_field_ref(exc, "detailMessage")^
    if msg != nil {
        return javaString_to_string(msg)
    }
    cause := get_object_field_ref(exc, "cause")^
    if cause != nil && exc != cause {
        return get_detail(cause)
    }
    return ""
}
