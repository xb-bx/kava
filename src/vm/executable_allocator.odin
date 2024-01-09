package vm
import "core:fmt"
import "core:mem/virtual"

EXE_ALIGNMENT :: 0x2000
MINIMAL_FREE_SIZE :: 0x20


ExeAllocator :: struct {
    chunks: [dynamic]^Chunk,
    free_executable_places: [dynamic]FreePlace, 
}
exealloc_init :: proc(allocator: ^ExeAllocator) {
    allocator.chunks = make([dynamic]^Chunk)
    allocator.free_executable_places = make([dynamic]FreePlace)
    exealloc_new_chunk(allocator, EXE_ALIGNMENT * 64)
}
exealloc_new_chunk :: proc(allocator: ^ExeAllocator, size: int = EXE_ALIGNMENT) {
    size := align_size(size + size_of(virtual.Memory_Block), EXE_ALIGNMENT) * 4 
    chunk := new_clone(Chunk { alloc_executable(uint(size)), size })
    append(&allocator.chunks, chunk) 
    append(&allocator.free_executable_places, FreePlace { chunk, 0, size }) 
}

exealloc_find_free :: proc(using allocator: ^ExeAllocator, size: int) -> Maybe(FreePlace) {
    i := 0 
    for i in 0..<len(free_executable_places) {
        free := &free_executable_places[i]
        if free.size > size {
            if free.size - size < MINIMAL_FREE_SIZE {
                res := free^
                remove_range(&free_executable_places, i, i + 1)
                return res
            } else  {
                res := FreePlace { free.chunk, free.offset, size }
                free.offset += size
                free.size -= size
                return res
            } 
        } else if free.size == size {
            res := free^
            remove_range(&free_executable_places, i, i + 1)
            return res
        }
    }    
    return nil
}
EXE_HEADER :: 8
exealloc_alloc :: proc(allocator: ^ExeAllocator, size: int) -> [^]u8 {
    size := align_size(size + EXE_HEADER, MINIMAL_FREE_SIZE)     
    free_place := exealloc_find_free(allocator, size)
    res: [^]u8 = nil
    if free_place != nil {
        res = transmute([^]u8)((transmute(int)free_place.(FreePlace).chunk.data + free_place.(FreePlace).offset))
    }
    else {
        exealloc_new_chunk(allocator, size)
        free_place = exealloc_find_free(allocator, size)
        res = transmute([^]u8)((transmute(int)free_place.(FreePlace).chunk.data + free_place.(FreePlace).offset))
    }
    (transmute(^int)res)^ = free_place.(FreePlace).size 
    return transmute([^]u8)(transmute(int)res + EXE_HEADER)
}

executable_is_ptr_inbounds_of :: proc(chunk: ^Chunk, ptr: rawptr) -> bool {
    start := transmute(int)chunk.data 
    end := start + chunk.size
    iptr := transmute(int)ptr
    if (iptr - EXE_HEADER - start) % MINIMAL_FREE_SIZE != 0 {
        return false 
    }
    return iptr >= start && iptr < end
}
executable_free :: proc(using allocator: ^ExeAllocator, ptr: [^]u8) {
    chunk: ^Chunk = nil
    for ch in chunks {  
        if executable_is_ptr_inbounds_of(ch, ptr) {
            chunk = ch
            break
        }
    }
    if chunk == nil {
        return
    }
    posible_free : ^FreePlace = nil
    ptr_offset := transmute(int)ptr - transmute(int)chunk.data - EXE_HEADER
    mem_size := (transmute(^int)(transmute(int)ptr - EXE_HEADER))^
    for &free in free_executable_places {
        if free.chunk == chunk && free.offset + free.size == ptr_offset {
            posible_free = &free  
            free.size += mem_size
            break
        } 
        else if free.chunk == chunk && free.offset - mem_size == ptr_offset {
            posible_free = &free
            free.offset = ptr_offset
            free.size += mem_size
            break
        }
    }
    if posible_free == nil {
        freeplace := FreePlace { chunk, ptr_offset, mem_size }
        append(&free_executable_places, freeplace)
    } else {
    }
}

alloc_executable :: proc(size: uint) -> [^]u8 {
    size := size
    data, err := virtual.memory_block_alloc(size, size, {})
    if err != virtual.Allocator_Error.None {
        panic("Failed to allocate executable memory")
    }
    prot := transmute(rawptr)(transmute(int)data.base & ~int(0xfff))
    ok := virtual.protect(prot, data.reserved, { virtual.Protect_Flag.Read, virtual.Protect_Flag.Write, virtual.Protect_Flag.Execute})
    if !ok {
        panic("Failed to allocate executable memory")
    }
    return data.base
}
