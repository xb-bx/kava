package classparser 
import "core:strings"
import "core:fmt"
Reader :: struct {
    bytes: []u8,
    position: int,
}

read_u64_be :: proc(using reader: ^Reader) -> Maybe(u64) {
    res := read_u64(reader)
    if res == nil {
        return nil
    }
    return cast(u64)(transmute(u64be)(res.(u64)))
}
read_u64 :: proc(using reader: ^Reader) -> Maybe(u64) {
    if position + 8 > len(bytes) {
        return nil
    }
    res: u64 = 0
    res |= read_byte_silent(reader, u64) 
    res |= (read_byte_silent(reader, u64) ) << 8
    res |= (read_byte_silent(reader, u64) ) << 16
    res |= (read_byte_silent(reader, u64) ) << 24
    res |= (read_byte_silent(reader, u64) ) << 32 
    res |= (read_byte_silent(reader, u64) ) << 40
    res |= (read_byte_silent(reader, u64) ) << 48
    res |= (read_byte_silent(reader, u64)  << 56) 
    return res
}

read_u16_be :: proc(using reader: ^Reader) -> Maybe(u16) {
    res := read_u16(reader)
    if res == nil {
        return nil
    }
    return cast(u16)(transmute(u16be)(res.(u16)))
}

read_u32_be :: proc(using reader: ^Reader) -> Maybe(u32) {
    res := read_u32(reader)
    if res == nil {
        return nil
    }
    return cast(u32)(transmute(u32be)(res.(u32)))
}
read_u16 :: proc(using reader: ^Reader) -> Maybe(u16) {
    if position + 2 > len(bytes) {
        return nil
    }
    res: u16 = 0
    res |= read_byte_silent(reader, u16) & 0xFF
    res |= (read_byte_silent(reader, u16) << 8) 
    return res
}
read_u32 :: proc(using reader: ^Reader) -> Maybe(u32) {
    if position + 4 > len(bytes) {
        return nil
    }
    res: u32 = 0
    res |= read_byte_silent(reader, u32)
    res |= (read_byte_silent(reader, u32) << 8) 
    res |= (read_byte_silent(reader, u32) << 16) 
    res |= (read_byte_silent(reader, u32) << 24) 
    return res
}
read_byte :: proc(using reader: ^Reader) -> Maybe(u8) {
    if position >= len(bytes) {
        return nil
    }
    res := bytes[position]
    position += 1
    return res
}
read_byte_silent :: proc(using reader: ^Reader, $T: typeid) -> T {
    res := bytes[position]
    position += 1
//     fmt.printf("%H", res)
    return cast(T)res & 0xff
}
read_string :: proc(using reader: ^Reader) -> Maybe(string) {
    cbytes := make([dynamic]u8)
    defer delete(cbytes)
    b := read_byte(reader)
    if b == nil {
        return nil
    }
    for b.(u8) > 0 {
        append(&cbytes, b.(u8))
        b = read_byte(reader)
    }
    return strings.clone_from_bytes(cbytes[:])
}

