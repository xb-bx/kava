package nobuild 
import "core:os"

when ODIN_OS == .Windows {
    KAVA_EXE :: "kava.exe"
    CLASSPARSER_EXE :: "classparser.exe"
} else {
    KAVA_EXE :: "kava"
    CLASSPARSER_EXE:: "classparser"
}


main :: proc() {
    if !os.exists("odin-zip") {
        run("git", "clone", "https://github.com/xb-bx/odin-zip")
        cd("odin-zip")
        when ODIN_OS == .Windows {
            run("./build.bat")
        }
        else {
            run("./build.sh")
        }
        cd("..")
    }

    collections: map[string]string = {"zip" = "odin-zip/src",  "kava" = "src", "libzip" = "odin-zip/libzip", }
    additional := [?]string {"-debug"}
    odin_build("src/classparser", output = CLASSPARSER_EXE, collections = collections, additional_args = additional[:])
    odin_build("src/vm", output = KAVA_EXE, collections = collections, additional_args = additional[:])
}
