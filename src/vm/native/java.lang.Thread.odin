package native
import kava "kava:vm"
/// registerNatives ()V
Thread_registerNatives :: proc "c" (env: ^^kava.JNINativeInterface, ) {
}
/// currentThread ()Ljava/lang/Thread;
Thread_currentThread :: proc "c" (env: ^^kava.JNINativeInterface, ) -> ^kava.ObjectHeader {
    return nil
}
