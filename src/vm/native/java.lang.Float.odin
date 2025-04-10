package native
import kava "kava:vm"


/// floatToRawIntBits (F)I
floatToRawIntBits :: proc "c" (env: ^kava.JNINativeInterface, float: f32) -> i32 {
    return transmute(i32)float
}
