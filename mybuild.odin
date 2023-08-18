package nobuild 
import "core:os"




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
    odin_build("src/vm", output = "kava", collections = collections)
}
