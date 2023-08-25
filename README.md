# KAVA is JVM written in odin

TODO:
- [X] Class parser
- [X] Type system
- [X] .jar loading
- [ ] standard classes(java.lang.*, java.io.* etc.)
- [ ] JIT(WIP ~30% done)
- [ ] JNI
- [ ] GC
- [ ] Multithreading

Goals:
- [ ] Run Minecraft


### Debugging with gdb

1. Build the project
2. Start gdb
3. run `jit-reader-load <path/to/kava>/gdbplugin.so`.

Now when you will step into jitted function you will see java bytecode
