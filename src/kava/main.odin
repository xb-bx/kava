package kava
import "kava:classparser"
import "x86asm:x86asm"
import "kava:shared"
import "core:os"
import "core:fmt"
import "core:strings"
import "core:path/filepath"
import "core:path/slashpath"
import "base:intrinsics"
import "core:slice"
import "core:time"
import "zip:zip"
import "core:sys/windows"
import "kava:vm/native"
import "kava:vm/net"
import "core:sys/unix"
import "core:unicode/utf16"
import "core:sync"
import kavavm "kava:vm"

OS_UNIX :: kavavm.OS_UNIX
error :: proc(str: string, args: ..any) {
    fmt.printf(str, ..args)
    fmt.println()
    os.exit(-1)
}
DIR_SEPARATOR :: ":" 
print_usage :: proc() {
    fmt.println("usage: kava [-options] class [args...]")
}
main :: proc() {
    using kavavm
    x86asm.set_formatter() 
    args := os.args[1:]
    if len(args) == 0 {
        print_usage()
        return
    }
    executable := os.args[0]
    executable_dir := filepath.dir(executable)
    classpaths:[dynamic]string = make([dynamic]string)
    combine := make([]string, 2)
    defer delete(combine)
    combine[0] = executable_dir
    combine[1] = "jre"
    append(&classpaths, filepath.join(combine))
    combine[1] = "runtime"
    append(&classpaths, filepath.join(combine))
    application:string = ""
    applicationargs:[]string = nil
    dump_jitted_class: string = ""
    dump_jitted_method: string = ""
    dump_jitted_descriptor: string = ""
    i := 0
    for i < len(args) {
        switch args[i] {
            case "-cp":
                if i + 1 >= len(args) {
                    error("Error: -cp requires class path specification")
                }  
                append(&classpaths, ..strings.split(args[i + 1], DIR_SEPARATOR))
                i += 1
            case "-dump_jitted":
                if i + 3 >= len(args) {
                    error("Error: -dump_jitted requires class, method and descriptor specification")
                }  
                dump_jitted_class = args[i + 1]
                dump_jitted_method = args[i + 2]
                dump_jitted_descriptor = args[i + 3]
                i += 3
            case:
                application = args[i]
                if i + 1 <= len(args) {
                    applicationargs = args[i + 1:]
                }
                i = len(args)
        }
        i += 1
    }
    if application == "" {
        print_usage()
        return
    }
    gc := new(GC)
    gc_init(gc)
    slice.reverse(classpaths[:])
    vm = new_clone(VM {
        classpaths = classpaths[:],
        classes = make(map[string]^Class),
        lambdaclasses = make(map[string]^Class),
        ctx = context,
        gc = gc,
        natives_table = make(map[^Method][^]u8),
        classobj_to_class_map = make(map[^ObjectHeader]^Class),
        native_intitializers = make(map[string]proc()),
        exe_allocator = {},
        stacktraces = make(map[int][dynamic]^StackEntry),
    })
    kavavm.current_tid = sync.current_thread_id()
    vm.stacktraces[current_tid] = nil
    stack_trace = &vm.stacktraces[current_tid]
    jni_init(vm)
    intern_init(&vm.internTable)
    exealloc_init(&vm.exe_allocator)
    prepare_after_jitted(vm)
    prepare_before_jitted(vm)
    native.add_initilizers(vm)
    net.add_initilizers(vm)
    for prim in PrimitiveType {
        make_primitive(vm, prim, primitive_names[prim], primitive_sizes[prim])
    }
    _ = load_class(vm , "java/lang/String")
    _ = load_class(vm , "java/lang/Class")
    app := load_class(vm, application)
    init_threads(vm)


    if app.is_err {
        error(app.error.(string))
    }
    if dump_jitted_class != "" {
        dump_class := load_class(vm, dump_jitted_class).value.(^Class)
        dump_method := find_method(dump_class, dump_jitted_method, dump_jitted_descriptor)
        if dump_method == nil {
            error("Method %s:%s:%s not found", dump_jitted_class, dump_jitted_method, dump_jitted_descriptor)
        }
        body_size: int = 0
        body := jit_method_lazy(vm, dump_method, &body_size) 
        assert(os.write_entire_file("dump.bin", slice.bytes_from_ptr(body, body_size)))
    }

    stopwatch := time.Stopwatch {}
    classinit := find_method(app.value.(^Class), "<clinit>", "()V")
    if classinit != nil {
        (transmute(proc "c" (^^JNINativeInterface, ))(classinit.jitted_body))(&vm.jni_env)
    }

    mainMethod := find_method(app.value.(^Class), "main", "([Ljava/lang/String;)V")
    if mainMethod == nil {
        error("Could not find entry point")
    }

    args_array: ^ArrayHeader = nil
    gc_alloc_array(vm, vm.classes["java/lang/String"], len(applicationargs), &args_array)
    args_slice := array_to_slice(^ObjectHeader, args_array)
    for arg,i in applicationargs {
        str : ^ObjectHeader = nil
        gc_alloc_string(vm, arg, &str)
        args_slice[i] = str 
    
    }
    
    stopwatch = time.Stopwatch {}
    time.stopwatch_start(&stopwatch)
    
    ((transmute(proc "c" (env: ^^JNINativeInterface, args: ^ArrayHeader))mainMethod.jitted_body))(&vm.jni_env, args_array)
    time.stopwatch_stop(&stopwatch)
    dur := time.stopwatch_duration(stopwatch)
    fmt.println("Execution took", dur)
    //for true {

    //}
}


