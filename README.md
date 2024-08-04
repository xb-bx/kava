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

- Build the project. 
Optionally you can build project with BREAKPOINT variable. The jit will insert int3 instruction at the start of the specified method. 
    ```sh
    BREAKPOINT='CLASS:METHOD:DESCRIPTOR' make all
    ```

- Start gdb. 
- When you will step into jitted function you will be able to see java bytecode. 
And also you can use command 'kava-locals' to print local variables.
#### For whatever reason debugging with src/gdbplugin doesnt work in latest gdb. Should work fine in gdb 11

