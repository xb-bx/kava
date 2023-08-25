package vm
@export
__jit_debug_descriptor: JitDescriptor = { 1, 1, nil, nil, }
@export
__jit_debug_register_code :: proc "c" () {}


JitCodeEntry :: struct {
    next_entry: ^JitCodeEntry,
    prev_entry: ^JitCodeEntry,
    symfile: [^]u8,
    size: u64,
}

JitDescriptor :: struct {
    version: u32,
    action_flags: u32,
    relevant_entry: ^JitCodeEntry,
    first_entry: ^JitCodeEntry,
}
