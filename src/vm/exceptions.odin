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
    set_object_field(nimpl, "message", transmute(int)message)
    rbp := 0
    target := throw_impl(vm, nimpl, &rbp)
    asm(^ObjectHeader) #side_effects #intel { "mov rdi, rax", ":rax" }(nimpl)
    asm(int) #side_effects #intel { "mov rbp, rax", ":rax" }(rbp)
    asm(int) #side_effects #intel { "jmp rax", ":rax" }(target)

}
throw_exception_string :: proc "c" (vm: ^VM, exception_name: string, message: string ) {
    messageobj : ^ObjectHeader = nil 
    gc_alloc_string(vm, message, &messageobj)
    throw_exception(vm, exception_name, messageobj)
} 
throw_impl :: proc "c" (vm: ^VM, exc: ^ObjectHeader, old_rbp: ^int) -> int {
    context = vm.ctx
    i := len(stacktrace) - 1
    items_to_remove := 0
    for i >= 0 {
        entry := stacktrace[i]
        table := entry.method.exception_table
        for exception in table {
            if exception.exception == exc.class ||  is_subtype_of(exc.class, exception.exception) {
                if entry.pc >= exception.start && entry.pc <= exception.end {
                    if items_to_remove > 0 {
                        start := len(stacktrace) - items_to_remove
                        remove_range(&stacktrace, start, start + items_to_remove)
                    }
                    old_rbp^ = entry.rbp
                    return transmute(int)entry.method.jitted_body + exception.offset 
                }
            }
        }
        items_to_remove += 1
        i -= 1
    }
        
    toString := transmute(proc "c" (^ObjectHeader) -> ^ObjectHeader)(jit_resolve_virtual(vm, exc, find_method(vm.classes["java/lang/Object"], "toString", "()Ljava/lang/String;"))^)    
    assert(toString != nil)
    str := toString(exc)
    msg := exc.class.name
    if str != nil {
        arr := transmute(^ArrayHeader)get_object_field(str, "value")
        chars := array_to_slice(u16, arr)
        msg = strings.clone_from_ptr(transmute(^u8)slice.as_ptr(chars), len(chars) * 2)
    }
    fmt.printf("Unhandled exception %s\n", msg)
    print_stack_trace()
    panic("")
}
