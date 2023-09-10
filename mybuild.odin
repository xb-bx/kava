package nobuild 
import "core:os"
import "core:fmt"
import "core:path/filepath"
import "core:odin/parser"
import "core:odin/ast"
import "core:slice"
import "core:strings"
when ODIN_OS == .Windows {
    KAVA_EXE :: "kava.exe"
    CLASSPARSER_EXE :: "classparser.exe"
} else {
    KAVA_EXE :: "kava"
    CLASSPARSER_EXE:: "classparser"
}

generate :: proc() {
    pkg, ok := parser.parse_package_from_path("src/vm")
    if !ok {
        fmt.println("fuck")
    }
    builder: strings.Builder = {}
    strings.builder_init(&builder)
    fmt.sbprintln(&builder, "package vm")
    fmt.sbprintln(&builder, "vm: ^VM = nil")
    fmt.sbprintln(&builder, "initialize_kava :: proc(vmm: ^VM) {")
    fmt.sbprintln(&builder, "    vm = vmm")
    fmt.sbprintln(&builder, "    kavaclassres := load_class(vm, \"kava/Kava\")")
    fmt.sbprintln(&builder, "    if kavaclassres.is_err { return }")
    fmt.sbprintln(&builder, "    kavaclass := kavaclassres.value.(^Class)")
    fmt.sbprintln(&builder, "    meth: ^Method = nil")
    for name, file in pkg.files {
        if filepath.base(name) == "kava_api.odin" {
            for decl in file.decls {
                if val, isval := decl.derived_stmt.(^ast.Value_Decl); isval {
                    if len(val.values) != 1 { 
                        continue
                    }
                    if proclit, is_proc := val.values[0].derived_expr.(^ast.Proc_Lit); is_proc {
                        if val.docs != nil && len(val.docs.list) > 0 {
                            
                            namenode :=val.names[0]
                            procname, res := strings.cut(file.src, namenode.pos.offset, namenode.end.offset - namenode.pos.offset)
                            splited := strings.split(strings.trim(val.docs.list[0].text, "/ "), " ")
                            defer delete(splited)
                            if len(splited) != 2 {
                                continue
                            }                         
                            fmt.sbprintf(&builder, "    meth = find_method(kavaclass, \"%s\", \"%s\")\n", splited[0], splited[1])
                            fmt.sbprintf(&builder, "    if meth != nil {{ replace_body(meth, transmute(rawptr)%s) }}\n", procname)
                        }
                    }
                }
            }
            
        }
    }
    fmt.sbprintf(&builder, "}}\n")
    res := strings.to_string(builder)
    defer delete(res)
    os.write_entire_file("src/vm/kava_api.generated.odin", slice.bytes_from_ptr(raw_data(res), len(res)))
}
main :: proc() {
    generate() 
    if !os.exists("odin-zip") {
        run("git", "clone", "https://github.com/xb-bx/odin-zip")
        cd("odin-zip")
        when ODIN_OS == .Windows {
            run("build.bat")
        }
        else {
            run("./build.sh")
        }
        cd("..")
    }
    if !os.exists("x86asm") {
        run("git", "clone", "https://github.com/xb-bx/x86asm")
    }
    args := os.args[1:]
    collections: map[string]string = {"zip" = "odin-zip/src",  "kava" = "src", "libzip" = "odin-zip/libzip", "x86asm" = "x86asm/src" }
    when ODIN_OS == .Windows {
        additional := [?]string { "-debug", "-extra-linker-flags:/STACK:4194304"}
    } else {
        additional := [?]string { "-debug",}
    }
    odin_build("src/classparser", output = CLASSPARSER_EXE, collections = collections, additional_args = additional[:])
    odin_build("src/vm", output = KAVA_EXE, collections = collections, additional_args = additional[:])
    odin_build("src/gdbplugin", "gdbplugin.so", collections, additional_args = additional[:], build_mode = .Dynamic)
    
    if len(args) > 0 && args[0] == "java" {
        packages := list_files("runtime/java")
        for pkg in packages {
            sources := list_files(pkg.fullpath)
            for source in sources {
                if filepath.ext(source.fullpath) == ".java" {
                    run("javac", "-cp", "runtime", source.fullpath)
                }
            }
        }
        packages = list_files("runtime/kava")
        for source in packages {
            if filepath.ext(source.fullpath) == ".java" {
                run("javac", "-cp", "runtime", source.fullpath)
            }
        }
       
    }
    
}
