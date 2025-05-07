package native
import kava "kava:vm"
import "core:fmt"
import "core:time"
import "core:sync"
import "core:thread"
/// registerNatives ()V
Thread_registerNatives :: proc "c" (env: ^^kava.JNINativeInterface, ) {
}
/// currentThread ()Ljava/lang/Thread;
Thread_currentThread :: proc "c" (env: ^^kava.JNINativeInterface, ) -> ^kava.ObjectHeader {
    return kava.cur_thread
}
/// sleep (J)V
Thread_sleep :: proc "c" (env: ^^kava.JNINativeInterface, sleep: i64) {
    time.sleep(time.Millisecond * time.Duration(sleep))
}
/// setPriority0 (I)V
Thread_setPriority0 :: proc "c" (env: ^^kava.JNINativeInterface, priority: i32 ) {
    // TODO: set priority
}
/// start0 ()V
Thread_start0 :: proc "c" (env: ^^kava.JNINativeInterface, this: ^kava.ObjectHeader) {
    context = (env^).vm.ctx
    thr := thread.create(proc (t: ^thread.Thread) {
        kava.current_tid = sync.current_thread_id()
        vm.stacktraces[kava.current_tid] = make([dynamic]^kava.StackEntry)
        kava.stack_trace = &vm.stacktraces[kava.current_tid]
        this := transmute(^kava.ObjectHeader)t.data
        kava.cur_thread = this
        meth := transmute(proc "c"(env: ^^kava.JNINativeInterface, this: ^kava.ObjectHeader))(kava.jit_resolve_virtual(vm, this, kava.find_method(vm.classes["java/lang/Thread"], "run", "()V"), nil)^)
        meth(&vm.jni_env, this)
        delete_key(&vm.stacktraces, kava.current_tid)
    })
    thr.data = this
    thread.start(thr)


}
