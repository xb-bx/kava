package native
import "kava:vm"


/// floatToRawIntBits (F)I
floatToRawIntBits :: proc "c" (float: f32) -> i32 {
    return transmute(i32)float
}
