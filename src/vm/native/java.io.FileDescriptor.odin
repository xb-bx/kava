package native

import kava "kava:vm"
import "core:os"

/// initIDs ()V
initIDS :: proc "c" () {}

/// set (I)J
FileDescriptor_set :: proc "c" (fd: i32) -> os.Handle {
    context = vm.ctx
    switch fd {
        case 0:
            return os.stdin
        case 1:
            return os.stdout
        case 2:
            return os.stderr
        case: 
            panic("")
    }

}
