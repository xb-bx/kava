package nobuild 
import "core:os"

when ODIN_OS == .Windows {
    KAVA_EXE :: "kava.exe"
} else {
    KAVA_EXE :: "kava"
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
    odin_build("src/classparser", output = "classparser", collections = collections)
    odin_build("src/vm", output = KAVA_EXE, collections = collections)
}
