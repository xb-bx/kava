package generator 
import "core:os"
import "core:fmt"
import "core:path/filepath"
import "core:path/slashpath"
import "core:odin/parser"
import "core:odin/ast"
import "core:slice"
import "core:strings"
import "base:intrinsics"
generate_native_methods :: proc(needs_generation: string, package_name: string) {
    package_path := fmt.aprintf("src/vm/%s", package_name)
    pkg, ok := parser.parse_package_from_path(package_path)
    if !ok {
        fmt.println("fuck")
    }
    classes := make([dynamic]string)
    for name, file in pkg.files {
        if strings.last_index(name, filepath.base(needs_generation)) >= 0 {
            classname_dots := slashpath.name(filepath.base(name), true)
            classname, _ := strings.replace_all(classname_dots, ".", "/")
            classname_underscored, _ := strings.replace_all(classname, "/", "_")
            append(&classes, classname_underscored)
            fmt.println(classname)
            builder: strings.Builder = {}
            strings.builder_init(&builder)
            fmt.sbprintf(&builder, "package %s\n", package_name)
            fmt.sbprintln(&builder, "import kava \"kava:vm\"")
            fmt.sbprintf(&builder, "initialize_%s :: proc() {{\n", classname_underscored)
            fmt.sbprintf(&builder,  "    classres := kava.load_class(vm, \"%s\")\n", classname)
            fmt.sbprintln(&builder, "    if classres.is_err { return }")
            fmt.sbprintln(&builder, "    class := classres.value.(^kava.Class)")
            fmt.sbprintln(&builder, "    meth: ^kava.Method = nil")
            for decl in file.decls {
                if val, isval := decl.derived_stmt.(^ast.Value_Decl); isval {
                    if len(val.values) != 1 { 
                        continue
                    }
                    if proclit, is_proc := val.values[0].derived_expr.(^ast.Proc_Lit); is_proc {
                        if val.docs != nil && len(val.docs.list) > 0 {
                            
                            namenode :=val.names[0]
                            procname := strings.cut(file.src, namenode.pos.offset, namenode.end.offset - namenode.pos.offset)
                            splited := strings.split(strings.trim(val.docs.list[0].text, "/ "), " ")
                            defer delete(splited)
                            if len(splited) == 2 {
                                fmt.sbprintf(&builder, "    meth = kava.find_method(class, \"%s\", \"%s\")\n", splited[0], splited[1])
                                fmt.sbprintf(&builder, "    if meth != nil {{ vm.natives_table[meth] = transmute([^]u8)%s }}\n", procname)
                            }
                            else if len(splited) == 3 {
                                fmt.sbprintf(&builder, "    meth = kava.find_method(class, \"%s\", \"%s\")\n", splited[0], splited[1])
                                fmt.sbprintf(&builder, "    if meth != nil {{ kava.replace_body(vm, meth, transmute(rawptr)%s) }}\n", procname)

                            }
                        }
                    }
                }
            }
            fmt.sbprintln(&builder, "}")
            res := strings.to_string(builder)
            defer delete(res)

            genpath := fmt.aprintf("src/vm/%s/%s.generated.odin", package_name, classname_dots)
            defer delete(genpath)
            handle, err := os.open(genpath, os.O_CREATE | os.O_WRONLY | os.O_TRUNC, 0o640)
            assert(err == nil)
            defer os.close(handle)
            os.write(handle, slice.bytes_from_ptr(raw_data(res), len(res)))

        }
    

    }
}
initializer :: proc(package_name: string) {
    package_path := fmt.aprintf("src/vm/%s", package_name)
    pkg, ok := parser.parse_package_from_path(package_path)
    if !ok {
        fmt.println("fuck")
    }
    builder: strings.Builder = {}
    strings.builder_init(&builder)
    fmt.sbprintf(&builder, "package %s\n", package_name)
    fmt.sbprintln(&builder, "import kava \"kava:vm\"")
    fmt.sbprintln(&builder, "vm: ^kava.VM = nil")
    fmt.sbprintln(&builder, "add_initilizers :: proc(vmm: ^kava.VM) {")
    fmt.sbprintln(&builder, "   vm = vmm")
    for filename,_ in pkg.files {
        if strings.last_index(filename, ".generated.odin") != -1 do continue
        file := filepath.stem(filename)
        classpath, _ := strings.replace_all(file, ".", "/")
        class, _ := strings.replace_all(file, ".", "_")
        fmt.sbprintf(&builder, "   vm.native_intitializers[\"%s\"] = initialize_%s\n", classpath, class)
    }
    fmt.sbprintln(&builder, "}")
    res := strings.to_string(builder)
    defer delete(res)
    init_path := fmt.aprintf("src/vm/%s/initialize.generated.odin", package_name)
    handle, err := os.open(init_path, os.O_CREATE | os.O_WRONLY | os.O_TRUNC, 0o640)
    assert(err == nil)
    defer os.close(handle)
    os.write(handle, slice.bytes_from_ptr(raw_data(res), len(res)))
}

main :: proc() {
    if os.args[1] == "initializer" {
        initializer(os.args[2])
    }
    else {
        generate_native_methods(os.args[1], os.args[2])
    }
}
