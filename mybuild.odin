package nobuild 

main :: proc() {
    run("odin", "build", "src/classparser", "-collection:kava=src")
}
