package shared
import "core:fmt"
Result :: struct($TOk: typeid, $TErr: typeid) {
    value: Maybe(TOk),
    error: Maybe(TErr),
    is_ok: bool,
    is_err: bool,
    
}
Ok :: proc($TErr: typeid, value: $TOk) -> Result(TOk, TErr) {
    return Result(TOk, TErr) {
        value = value,
        error = nil,
        is_ok = true,
        is_err = false,
    } 
}
when ODIN_DEBUG {
    Err :: proc($TOk: typeid, value: $TErr, loc := #caller_location) -> Result(TOk, TErr) {
        
        return Result(TOk, TErr) {
            value = nil,
            error = fmt.aprintf("%s at %v", value, loc),
            is_ok = false,
            is_err = true,
        }
    }
}
else {
    Err :: proc($TOk: typeid, value: $TErr) -> Result(TOk, TErr) {
        return Result(TOk, TErr) {
            value = nil,
            error = value,
            is_ok = false,
            is_err = true,
        }
    }
}
