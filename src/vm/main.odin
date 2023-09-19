package vm
import "kava:classparser"
import "x86asm:x86asm"
import "kava:shared"
import "core:os"
import "core:fmt"
import "core:strings"
import "core:path/filepath"
import "core:intrinsics"
import "core:slice"
import "core:time"
import "zip:zip"
import "core:sys/windows"

error :: proc(str: string, args: ..any) {
    fmt.printf(str, ..args)
    fmt.println()
    os.exit(-1)
}
when ODIN_OS == .Linux {
    DIR_SEPARATOR :: ":" 
} else when ODIN_OS == .Windows {
    DIR_SEPARATOR :: ";"
}
print_usage :: proc() {
    fmt.println("usage: kava [-options] class [args...]")
}
main :: proc() {
    x86asm.set_formatter() 
    args := os.args[1:]
    if len(args) == 0 {
        print_usage()
        return
    }
    classpaths:[]string = nil
    application:string = ""
    applicationargs:[]string = nil
    i := 0
    for i < len(args) {
        switch args[i] {
            case "-cp":
                if i + 1 >= len(args) {
                    error("Error: -cp requires class path specification")
                }  
                classpaths = strings.split(args[i + 1], DIR_SEPARATOR)
                i += 1
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
    vm := VM {
        classpaths = classpaths,
        classes = make(map[string]^Class),
        lambdaclasses = make(map[string]^Class),
        ctx = context,
        gc = gc,
    
    }
    for prim in PrimitiveType {
        make_primitive(&vm, prim, primitive_names[prim], primitive_sizes[prim])
    }
    app := load_class(&vm, application)
    if app.is_err {
        error(app.error.(string))
    }
    initialize_kava(&vm)
    stopwatch := time.Stopwatch {}

    for name, class in vm.classes {
        initializer := find_method(class, "<clinit>", "()V")
        if initializer != nil && !class.class_initializer_called {
            (transmute(proc "c" ())initializer.jitted_body)()
        }
        else {
            class.class_initializer_called = true;
        }
    }
    mainMethod := find_method(app.value.(^Class), "main", "([Ljava/lang/String;)V")
    if mainMethod == nil {
        error("Could not find entry point")
    }
    args_array: ^ArrayHeader = nil
    gc_alloc_array(&vm, vm.classes["java/lang/String"], len(applicationargs), &args_array)
    args_slice := array_to_slice(^ObjectHeader, args_array)
    for arg,i in applicationargs {
        str : ^ObjectHeader = nil
        gc_alloc_string(&vm, arg, &str)
        args_slice[i] = str 
    
    }
    
    stopwatch = time.Stopwatch {}
    time.stopwatch_start(&stopwatch)
    ((transmute(proc "c" (args: ^ArrayHeader))mainMethod.jitted_body))(args_array)
    time.stopwatch_stop(&stopwatch)
    dur := time.stopwatch_duration(stopwatch)
    fmt.println("Execution took", dur)

//     for k,v in vm.classes {
//         fmt.println(k, "=", v.name, v.class_type)
//         for field in v.fields {
//             fmt.println(field.name, "=", field.type.name)
//         }
//         for method in v.methods {
//             fmt.println(method.name, "=", method.ret_type.name)
//         }
//     }
}

