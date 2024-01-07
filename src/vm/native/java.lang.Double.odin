package native

/// longBitsToDouble (J)D
longBitsToDouble :: proc "c"(long: i64) -> f64 {
    return transmute(f64)long
}
/// doubleToRawLongBits (D)J
doubleToRawLongBits :: proc "c" (double: f64) -> i64 {
    return transmute(i64)double
}
