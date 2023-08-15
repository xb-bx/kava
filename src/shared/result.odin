package shared
Result :: struct($TOk: typeid, $TErr: typeid) {
    value: Maybe(TOk),
    error: Maybe(TErr),
    is_ok: bool,
    is_err: bool,
    
}
Ok :: proc($TOk: typeid, $TErr: typeid, value: TOk) -> Result(TOk, TErr) {
    return Result(TOk, TErr) {
        value = value,
        error = nil,
        is_ok = true,
        is_err = false,
    } 
}
Err :: proc($TOk: typeid, $TErr: typeid, value: TErr) -> Result(TOk, TErr) {
    return Result(TOk, TErr) {
        value = nil,
        error = value,
        is_ok = false,
        is_err = true,
    } 
}
