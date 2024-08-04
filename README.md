# KAVA is JVM written in odin

TODO:
- [X] Class parser
- [X] Type system
- [X] .jar loading
- [ ] JIT(WIP ~50% done)
- [ ] JNI
- [X] GC
- [ ] Multithreading

Goals:
- [ ] Run Minecraft

# Building 
run 
```sh
make all
```
## on Windows
use [Cygwin](https://www.cygwin.com/)


### Debugging with gdb

1. Build the project
2. Start gdb
3. run `jit-reader-load <path/to/kava>/gdbplugin.so`.

Now when you will step into jitted function you will see java bytecode
