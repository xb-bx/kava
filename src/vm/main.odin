package vm
import "kava:classparser"
import "kava:shared"
import "core:os"
import "core:fmt"
import "core:strings"
import "core:path/filepath"
import "core:intrinsics"
import "core:slice"
import "zip:zip"

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
    vm := VM {
        classpaths = classpaths,
        classes = make(map[string]^Class),
    }
    for prim in PrimitiveType {
        make_primitive(&vm, prim, primitive_names[prim])
    }
    app := load_class(&vm, application)
    if app.is_err {
        error(app.error.(string))
    }
    methods := vm.classes["HelloWorld"].methods
    main : ^Method = nil
    for method in &methods {
        if method.name == "main" {
            main = &method
            break
        }
    }
    blocks := (split_method_into_codeblocks(&vm, main))
    fmt.print("locals: ")
    for local in main.locals {
        fmt.printf("%s ", local.name)
    }
    fmt.println()
    for block in blocks {
        fmt.printf("start: %i end: %i\n", block.start, block.end)
        fmt.printf("stack: ")
        for typ in block.stack_at_start.types {
            fmt.print(typ.name)
            fmt.print(" ")
        }
        fmt.println()
    }
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

