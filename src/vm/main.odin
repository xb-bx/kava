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
        ctx = context,
    }
    fmt.println(classpaths)
    for prim in PrimitiveType {
        make_primitive(&vm, prim, primitive_names[prim], primitive_sizes[prim])
    }
    app := load_class(&vm, application)
    if app.is_err {
        error(app.error.(string))
    }
    initialize_kava(&vm)
    for class_name, class in vm.classes {
        fmt.printf("Class %s size: %i\n", class_name, class.size)
        if class.instance_fields != nil {
            for field in class.instance_fields {
                fmt.println(field.name, field.offset)        
            }
        }
        for &method in class.methods {
            if hasFlag(method.access_flags, classparser.MethodAccessFlags.Native | classparser.MethodAccessFlags.Abstract) {
                continue
            }
            fmt.printf("  Method %s:%s\n", method.name, method.ret_type.name)

            blocks := (split_method_into_codeblocks(&vm, &method))
            if blocks.is_err {
                print_verification_error(blocks.error.(VerificationError))
                error("")
            }
            fmt.print("    locals: ")
            for local in method.locals {
                fmt.printf("%s ", local.name)
            }
            fmt.println()
            for &block in blocks.value.([]CodeBlock) {
                print_codeblock(&block)
            }
            {
                jit_method(&vm, &method, blocks.value.([]CodeBlock))
            }
        }
    }
    for name, class in vm.classes {
        initializer := find_method(class, "<clinit>", "()V")
        if initializer != nil && !class.class_initializer_called {
            (transmute(proc "c" ())initializer.jitted_body)()
        }
        else {
            class.class_initializer_called = true;
        }
    }
    for method in app.value.(^Class).methods {
        if method.name == "main" {
            val := (transmute(proc "c"() -> i32) method.jitted_body)()
            fmt.println(val)
            return
        }
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

