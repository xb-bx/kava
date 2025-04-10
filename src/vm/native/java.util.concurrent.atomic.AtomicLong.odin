package native

import kava "kava:vm"

/// VMSupportsCS8 ()Z
VMSupportsCS8 :: proc "c" (env: ^kava.JNINativeInterface, ) -> bool {
    return false
}
