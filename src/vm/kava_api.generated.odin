package vm
vm: ^VM = nil
initialize_kava :: proc(vmm: ^VM) {
    vm = vmm
    kavaclassres := load_class(vm, "kava/Kava")
    if kavaclassres.is_err { return }
    kavaclass := kavaclassres.value.(^Class)
    meth: ^Method = nil
    meth = find_method(kavaclass, "write", "(JI)V")
    if meth != nil { replace_body(meth, transmute(rawptr)write_byte) }
    meth = find_method(kavaclass, "getStdout", "()Ljava/io/FileOutputStream;")
    if meth != nil { replace_body(meth, transmute(rawptr)getStdout) }
    meth = find_method(kavaclass, "flush", "(J)V")
    if meth != nil { replace_body(meth, transmute(rawptr)flush) }
}
