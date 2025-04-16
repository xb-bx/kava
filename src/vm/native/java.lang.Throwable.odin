package native

import kava "kava:vm"

/// fillInStackTrace (I)Ljava/lang/Throwable;

fillInStackTrace :: proc "c" () -> rawptr { return nil } 


/// printStackTrace (Ljava/lang/Throwable$PrintStreamOrWriter;)V replace
printStackTrace :: proc "c" (env: ^^kava.JNINativeInterface, ) { return }
