package vm
TypeStack :: struct {
    types: []^Class,
    count: int,
    cap: int,
}
stack_pop :: proc(using stack: ^TypeStack) -> ^Class {
    if count == 0 {
        return nil
    }
    res := types[count - 1]
    count -= 1
    return res
}
stack_push :: proc(using stack: ^TypeStack, type: ^Class) -> bool {
    if count == cap {
        return false
    }
    types[count] = type
    count += 1
    return true
}
make_stack :: proc(cap: int) -> TypeStack {
    return TypeStack {
        types = make([]^Class, cap),
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
    for typ, i in stack.types {
        if i >= stack.count {break}
        if typ != other.types[i] {
            return false
        }
    }
    return true
}
