package native
import kava "kava:vm"
/// registerNatives ()V
Thread_registerNatives :: proc "c" () {
}
/// currentThread ()Ljava/lang/Thread;
Thread_currentThread :: proc "c" () -> ^kava.ObjectHeader {
    return nil
}
