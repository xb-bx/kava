package vm
import "core:sync"
@(thread_local)
cur_thread: ^ObjectHeader
@(thread_local)
stack_trace: ^[dynamic]^StackEntry

init_threads :: proc(vm: ^VM) -> ^ObjectHeader {
    current_tid = sync.current_thread_id()
    threadgroup_class := load_class(vm, "java/lang/ThreadGroup").value.(^Class)
    threadgroup_ctor := transmute(proc "c" (env: ^^JNINativeInterface, this: ^ObjectHeader))(find_method(threadgroup_class, "<init>", "()V").jitted_body)
    threadgroup_clinit := find_method(threadgroup_class, "<clinit>", "()V")
    if threadgroup_clinit != nil do jit_ensure_clinit_called_body(vm, threadgroup_clinit)

    threadgroup: ^ObjectHeader = nil
    gc_alloc_object(vm, threadgroup_class, &threadgroup)
    threadgroup_ctor(&vm.jni_env, threadgroup)

    main_thread_class := load_class(vm, "kava/MainThread").value.(^Class)
    main_thread_ctor := transmute(proc "c" (env: ^^JNINativeInterface, this: ^ObjectHeader, group: ^ObjectHeader, runnable: ^ObjectHeader, name: ^ObjectHeader, stack_size: i64))(find_method_virtual(main_thread_class, "<init>", "(Ljava/lang/ThreadGroup;Ljava/lang/Runnable;Ljava/lang/String;J)V").jitted_body)
    main_thread_clinit := find_method(main_thread_class.super_class, "<clinit>", "()V")
    if threadgroup_clinit != nil do jit_ensure_clinit_called_body(vm, main_thread_clinit)

    main_thread: ^ObjectHeader = nil
    gc_alloc_object(vm, main_thread_class, &main_thread)
    cur_thread = main_thread
    thread_name: ^ObjectHeader = nil
    gc_alloc_string(vm, "MainThread", &thread_name)
    prio := transmute(^i32)get_object_field_ref(main_thread, "priority")
    prio ^= 5
    main_thread_ctor(&vm.jni_env, main_thread, threadgroup, nil, thread_name, 69)
    append(&vm.gc.temp_roots, main_thread)
    append(&vm.gc.temp_roots, threadgroup)
    return main_thread
}
monitor_enter :: proc "c" (vm: ^VM, monitor: ^Monitor) {
    context = vm.ctx
    if monitor.tid == current_tid {
        monitor.count += 1
    } else {
        sync.mutex_lock(&monitor.mutex)
        monitor.count = 1
        monitor.tid = current_tid
    }
}
monitor_exit :: proc "c" (vm: ^VM, monitor: ^Monitor) {
    context = vm.ctx
    assert(monitor.tid == current_tid) 
    assert(monitor.count > 0) 
    monitor.count -= 1
    if monitor.count == 0 {
        monitor.tid = 0
        monitor.count = 0
        sync.mutex_unlock(&monitor.mutex)
    }
}

Monitor :: struct {
    mutex: sync.Mutex,
    count: int,
    tid: int,
}
