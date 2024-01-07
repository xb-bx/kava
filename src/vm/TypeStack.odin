package vm
StackType :: struct {
    class: ^Class,
    is_null: bool,
}
TypeStack :: struct {
    types: []StackType,
    count: int,
    cap: int,
}
stack_pop_class :: proc(using stack: ^TypeStack) -> ^Class { 
    if count == 0 {
        return nil
    }
    res := types[count - 1]
    count -= 1
    return res.class
}
stack_pop :: proc(using stack: ^TypeStack) -> ^StackType {
    if count == 0 {
        return nil
    }
    res := &types[count - 1]
    count -= 1
    return res
}
stack_push :: proc(using stack: ^TypeStack, type: ^Class, is_null: bool = false) -> bool {
    if count == cap {
        return false
    }
    types[count].class = type
    types[count].is_null = is_null
    count += 1
    return true
}
make_stack :: proc(cap: int) -> TypeStack {
    return TypeStack {
        types = make([]StackType, cap),
        cap = cap,
        count = 0,
    }
}
delete_stack :: proc(stack: TypeStack) {
    delete(stack.types)
} 
copy_stack :: proc(stack: TypeStack) -> TypeStack {
    res := make_stack(stack.cap)
    for type, i in stack.types {
        if i >= stack.count {
            break
        }
        res.types[i] = type  
    }
    res.count = stack.count
    return res
} 
stack_eq :: proc(stack: ^TypeStack, other: ^TypeStack) -> bool {
    if stack.count != other.count {
        return false    
    }
//     for typ, i in stack.types {
//         if i >= stack.count {break}
//         if typ.class != other.types[i].class || !is_subtype_of(typ.class, other.types[i].class) {
//             return false
//         }
//     }
    return true
}
