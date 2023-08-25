package shared
import "core:fmt"
import "core:runtime"
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
Err :: proc($TOk: typeid, value: $TErr) -> Result(TOk, TErr) {
    return Result(TOk, TErr) {
        value = nil,
        error = value,
        is_ok = false,
        is_err = true,
    }
}
Symbol :: struct {
    file_len: int,
    file: cstring,
    function_len: int,
    function: cstring,
    line_mapping_len: int,
    line_mapping: [^]LineMapping,
    ctx: runtime.Context,
    start: int,
    end: int,

}
LineMapping :: struct {
    line: i32,
    pc: int,
}
