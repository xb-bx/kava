package classparser
import "core:fmt"
import "core:os"
import "core:strings"
import "kava:shared"


JAVA_VERSION :: 52 // Java 8

TableSwitch :: struct {
    offset: int,
    opcode: Opcode,
    default: int,
    low: int,
    high: int,
    offsets: []int,

}
Instruction :: union {
    SimpleInstruction,    
    TableSwitch,
}
Operand :: union {
    OneOperand,
    TwoOperands,
}
OneOperand :: struct {
    op: int,
}
TwoOperands :: struct {
    op1: int,
    op2: int,
}
SimpleInstruction :: struct {
    offset: int,
    opcode: Opcode,
    operand: Operand,
}

Opcode :: enum {
    aaload = 0x32,
    aastore = 0x53,
    aconst_null = 0x01,
    aload = 0x19,
    aload_0 = 0x2a,
    aload_1 = 0x2b,
    aload_2 = 0x2c,
    aload_3 = 0x2d,
    anewarray = 0xbd,
    areturn = 0xb0,
    arraylength = 0xbe,
    astore = 0x3a,
    astore_0 = 0x4b,
    astore_1 = 0x4c,
    astore_2 = 0x4d,
    astore_3 = 0x4e,
    athrow = 0xbf,
    baload = 0x33,
    bastore = 0x54,
    bipush = 0x10,
    breakpoint = 0xca,
    caload = 0x34,
    castore = 0x55,
    checkcast = 0xc0,
    d2f = 0x90,
    d2i = 0x8e,
    d2l = 0x8f,
    dadd = 0x63,
    daload = 0x31,
    dastore = 0x52,
    dcmpg = 0x98,
    dcmpl = 0x97,
    dconst_0 = 0x0e,
    dconst_1 = 0x0f,
    ddiv = 0x6f,
    dload = 0x18,
    dload_0 = 0x26,
    dload_1 = 0x27,
    dload_2 = 0x28,
    dload_3 = 0x29,
    dmul = 0x6b,
    dneg = 0x77,
    drem = 0x73,
    dreturn = 0xaf,
    dstore = 0x39,
    dstore_0 = 0x47,
    dstore_1 = 0x48,
    dstore_2 = 0x49,
    dstore_3 = 0x4a,
    dsub = 0x67,
    dup = 0x59,
    dup_x1 = 0x5a,
    dup_x2 = 0x5b,
    dup2 = 0x5c,
    dup2_x1 = 0x5d,
    dup2_x2 = 0x5e,
    f2d = 0x8d,
    f2i = 0x8b,
    f2l = 0x8c,
    fadd = 0x62,
    faload = 0x30,
    fastore = 0x51,
    fcmpg = 0x96,
    fcmpl = 0x95,
    fconst_0 = 0x0b,
    fconst_1 = 0x0c,
    fconst_2 = 0x0d,
    fdiv = 0x6e,
    fload = 0x17,
    fload_0 = 0x22,
    fload_1 = 0x23,
    fload_2 = 0x24,
    fload_3 = 0x25,
    fmul = 0x6a,
    fneg = 0x76,
    frem = 0x72,
    freturn = 0xae,
    fstore = 0x38,
    fstore_0 = 0x43,
    fstore_1 = 0x44,
    fstore_2 = 0x45,
    fstore_3 = 0x46,
    fsub = 0x66,
    getfield = 0xb4,
    getstatic = 0xb2,
    goto = 0xa7,
    goto_w = 0xc8,
    i2b = 0x91,
    i2c = 0x92,
    i2d = 0x87,
    i2f = 0x86,
    i2l = 0x85,
    i2s = 0x93,
    iadd = 0x60,
    iaload = 0x2e,
    iand = 0x7e,
    iastore = 0x4f,
    iconst_m1 = 0x02,
    iconst_0 = 0x03,
    iconst_1 = 0x04,
    iconst_2 = 0x05,
    iconst_3 = 0x06,
    iconst_4 = 0x07,
    iconst_5 = 0x08,
    idiv = 0x6c,
    if_acmpeq = 0xa5,
    if_acmpne = 0xa6,
    if_icmpeq = 0x9f,
    if_icmpge = 0xa2,
    if_icmpgt = 0xa3,
    if_icmple = 0xa4,
    if_icmplt = 0xa1,
    if_icmpne = 0xa0,
    ifeq = 0x99,
    ifge = 0x9c,
    ifgt = 0x9d,
    ifle = 0x9e,
    iflt = 0x9b,
    ifne = 0x9a,
    ifnonnull = 0xc7,
    ifnull = 0xc6,
    iinc = 0x84,
    iload = 0x15,
    iload_0 = 0x1a,
    iload_1 = 0x1b,
    iload_2 = 0x1c,
    iload_3 = 0x1d,
    impdep1 = 0xfe,
    impdep2 = 0xff,
    imul = 0x68,
    ineg = 0x74,
    instanceof = 0xc1,
    invokedynamic = 0xba,
    invokeinterface = 0xb9,
    invokespecial = 0xb7,
    invokestatic = 0xb8,
    invokevirtual = 0xb6,
    ior = 0x80,
    irem = 0x70,
    ireturn = 0xac,
    ishl = 0x78,
    ishr = 0x7a,
    istore = 0x36,
    istore_0 = 0x3b,
    istore_1 = 0x3c,
    istore_2 = 0x3d,
    istore_3 = 0x3e,
    isub = 0x64,
    iushr = 0x7c,
    ixor = 0x82,
    jsr_depr = 0xa8,
    jsr_w_depr = 0xc9,
    l2d = 0x8a,
    l2f = 0x89,
    l2i = 0x88,
    ladd = 0x61,
    laload = 0x2f,
    land = 0x7f,
    lastore = 0x50,
    lcmp = 0x94,
    lconst_0 = 0x09,
    lconst_1 = 0x0a,
    ldc = 0x12,
    ldc_w = 0x13,
    ldc2_w = 0x14,
    ldiv = 0x6d,
    lload = 0x16,
    lload_0 = 0x1e,
    lload_1 = 0x1f,
    lload_2 = 0x20,
    lload_3 = 0x21,
    lmul = 0x69,
    lneg = 0x75,
    lookupswitch = 0xab,
    lor = 0x81,
    lrem = 0x71,
    lreturn = 0xad,
    lshl = 0x79,
    lshr = 0x7b,
    lstore = 0x37,
    lstore_0 = 0x3f,
    lstore_1 = 0x40,
    lstore_2 = 0x41,
    lstore_3 = 0x42,
    lsub = 0x65,
    lushr = 0x7d,
    lxor = 0x83,
    monitorenter = 0xc2,
    monitorexit = 0xc3,
    multianewarray = 0xc5,
    new = 0xbb,
    newarray = 0xbc,
    nop = 0x00,
    pop = 0x57,
    pop2 = 0x58,
    putfield = 0xb5,
    putstatic = 0xb3,
    ret_depr = 0xa9,
    _return = 0xb1,
    saload = 0x35,
    sastore = 0x56,
    sipush = 0x11,
    swap = 0x5f,
    tableswitch = 0xaa,
    wide = 0xc4,
}

BytecodeBehaivour :: enum {
    REF_getField = 1,
    REF_getStatic,
    REF_putField,
    REF_putStatic,
    REF_invokeVirtual, 
    REF_invokeStatic, 
    REF_invokeSpecial, 
    REF_newInvokeSpecial, 
    REF_invokeInterface, 
}
AccessFlags :: enum u16 {
    Public = 0x0001,
    Final = 0x0010,
    Super = 0x0020,
    Interface = 0x0200,
    Abstract = 0x0400,
    Synthetic = 0x1000,
    Anotation = 0x2000,
    Enum = 0x4000,
}
FieldInfo :: struct {
    access_flags: AccessFlags,
    name_index: u16,
    descriptor_index: u16,
    attributes: []AttributeInfo,
}
AttributeInfo :: struct {
    name_index: u16,
    info: []u8,
}
ClassFile :: struct {
    minor_version : u16,
    major_version : u16,
    constant_pool : []ConstantPoolInfo,
    access_flags: AccessFlags,
    this_class: u16,
    super_class: u16,
    interfaces: []u16,
    fields: []FieldInfo,
    methods: []MethodInfo,
    attributes: []AttributeInfo,
}
ConstantPoolInfo :: union {
    ClassInfo,
    MethodRefInfo, 
    FieldRefInfo, 
    NameAndTypeInfo,
    UTF8Info,
    StringInfo, 
    IntegerInfo,
    InterfaceMethodRefInfo,
    FloatInfo,
    LongInfo,
    DoubleInfo,
    StoopitJava8ByteConstantTakeTwoPlacesInConstantPool,
    MethodHandleInfo,
    MethodTypeInfo,

}
InvokeDynamicInfo :: struct {
    bootstrap_method_attr_index: u16,
    name_and_type_index: u16,
}
MethodTypeInfo :: struct {
    descriptor_index: u16,
}
MethodHandleInfo :: struct {
    reference_kind: BytecodeBehaivour,
    reference_index: u16,
}
StoopitJava8ByteConstantTakeTwoPlacesInConstantPool :: struct {}
LongInfo :: struct {
    value: i64,
}
DoubleInfo :: struct {
    value: f64,
}

IntegerInfo :: struct {
    value: i32,
}
FloatInfo :: struct {
    value: f32,
}
FieldRefInfo :: struct {
    class_index: u16,
    name_and_type_index: u16,
}
InterfaceMethodRefInfo :: struct {
    class_index: u16,
    name_and_type_index: u16,
}
MethodRefInfo :: struct {
    class_index: u16,
    name_and_type_index: u16,
}
ClassInfo :: struct {
    name_index: u16,
}
NameAndTypeInfo :: struct {
    name_index: u16,
    descriptor_index: u16,
}
UTF8Info :: struct {
    str: string,
}
StringInfo :: struct {
    string_index: u16,
}
MethodInfo :: struct {
    access_flags: AccessFlags,
    name_index: u16,
    descriptor_index: u16,
    attributes: []AttributeInfo,
    bytecode: Maybe(CodeAttribute),
}
CodeAttribute :: struct {
    max_stack: u16,
    max_locals: u16,
    code: []Instruction,
    exception_table: []ExceptionInfo,
    attributes: []AttributeInfo,
}
ExceptionInfo :: struct {
    start_pc: u16,
    end_pc: u16,
    handler_pc: u16,
    catch_type: u16,
}
print_flags :: proc(flags: AccessFlags) {
    wasprev := false
    for flag in AccessFlags {
        if cast(int)flags & cast(int)flag == 1 {
            if wasprev {
                fmt.print(" | ")
            }
            fmt.print(flag)
            wasprev = true
        }
        
    } 
}
print_usage :: proc() {
    fmt.println("usage: classparser <classfile>")
}
error :: proc(str: string, args: ..any) {
    fmt.printf(str, ..args)
    os.exit(-1)
}
delete_attr :: proc(attr: AttributeInfo) {
    if attr.info != nil {
        delete(attr.info)
    }
}
single_op_b :: proc(b: u8) -> OneOperand{
    return OneOperand {
        op = cast(int)b,
    }
}
single_op_s :: proc(b: u16) -> OneOperand{
    return OneOperand {
        op = cast(int)b,
    }
}
two_op :: proc(op1: int, op2: int) -> TwoOperands {
    return TwoOperands {
        op1 = op1,
        op2 = op2,
    }
}
single_op :: proc(b: int) -> OneOperand{
    return OneOperand {
        op = b,
    }
}
hardcoded_opcodes := map[Opcode]SimpleInstruction {
    Opcode.aload_0 = SimpleInstruction { opcode = Opcode.aload, operand = single_op(0) },
    Opcode.aload_1 = SimpleInstruction { opcode = Opcode.aload, operand = single_op(1) },
    Opcode.aload_2 = SimpleInstruction { opcode = Opcode.aload, operand = single_op(2) },
    Opcode.aload_3 = SimpleInstruction { opcode = Opcode.aload, operand = single_op(3) },
    Opcode.astore_0 = SimpleInstruction { opcode = Opcode.astore, operand = single_op(0) },
    Opcode.astore_1 = SimpleInstruction { opcode = Opcode.astore, operand = single_op(1) },
    Opcode.astore_2 = SimpleInstruction { opcode = Opcode.astore, operand = single_op(2) },
    Opcode.astore_3 = SimpleInstruction { opcode = Opcode.astore, operand = single_op(3) },

    Opcode.fstore_0 = SimpleInstruction { opcode = Opcode.fstore, operand = single_op(0) },
    Opcode.fstore_1 = SimpleInstruction { opcode = Opcode.fstore, operand = single_op(1) },
    Opcode.fstore_2 = SimpleInstruction { opcode = Opcode.fstore, operand = single_op(2) },
    Opcode.fstore_3 = SimpleInstruction { opcode = Opcode.fstore, operand = single_op(3) },
    Opcode.fload_0 = SimpleInstruction { opcode = Opcode.fload, operand = single_op(0) },
    Opcode.fload_1 = SimpleInstruction { opcode = Opcode.fload, operand = single_op(1) },
    Opcode.fload_2 = SimpleInstruction { opcode = Opcode.fload, operand = single_op(2) },
    Opcode.fload_3 = SimpleInstruction { opcode = Opcode.fload, operand = single_op(3) },



    Opcode.istore_0 = SimpleInstruction { opcode = Opcode.istore, operand = single_op(0) },
    Opcode.istore_1 = SimpleInstruction { opcode = Opcode.istore, operand = single_op(1) },
    Opcode.istore_2 = SimpleInstruction { opcode = Opcode.istore, operand = single_op(2) },
    Opcode.istore_3 = SimpleInstruction { opcode = Opcode.istore, operand = single_op(3) },
    Opcode.iload_0 = SimpleInstruction { opcode = Opcode.iload, operand = single_op(0) },
    Opcode.iload_1 = SimpleInstruction { opcode = Opcode.iload, operand = single_op(1) },
    Opcode.iload_2 = SimpleInstruction { opcode = Opcode.iload, operand = single_op(2) },
    Opcode.iload_3 = SimpleInstruction { opcode = Opcode.iload, operand = single_op(3) },

    Opcode.lstore_0 = SimpleInstruction { opcode = Opcode.lstore, operand = single_op(0) },
    Opcode.lstore_1 = SimpleInstruction { opcode = Opcode.lstore, operand = single_op(1) },
    Opcode.lstore_2 = SimpleInstruction { opcode = Opcode.lstore, operand = single_op(2) },
    Opcode.lstore_3 = SimpleInstruction { opcode = Opcode.lstore, operand = single_op(3) },

    Opcode.lload_0 = SimpleInstruction { opcode = Opcode.lload, operand = single_op(0) },
    Opcode.lload_1 = SimpleInstruction { opcode = Opcode.lload, operand = single_op(1) },
    Opcode.lload_2 = SimpleInstruction { opcode = Opcode.lload, operand = single_op(2) },
    Opcode.lload_3 = SimpleInstruction { opcode = Opcode.lload, operand = single_op(3) },

    Opcode.iconst_m1 = SimpleInstruction { opcode = Opcode.iconst_m1, operand = nil },
    Opcode.iconst_0 = SimpleInstruction { opcode = Opcode.iconst_0, operand = nil },
    Opcode.iconst_1 = SimpleInstruction { opcode = Opcode.iconst_1, operand = nil },
    Opcode.iconst_2 = SimpleInstruction { opcode = Opcode.iconst_2, operand = nil },
    Opcode.iconst_3 = SimpleInstruction { opcode = Opcode.iconst_4, operand = nil },
    Opcode.iconst_4 = SimpleInstruction { opcode = Opcode.iconst_4, operand = nil },
    Opcode.iconst_5 = SimpleInstruction { opcode = Opcode.iconst_5, operand = nil },
    
    Opcode.dstore_0 = SimpleInstruction { opcode = Opcode.dstore, operand = single_op(0) },
    Opcode.dstore_1 = SimpleInstruction { opcode = Opcode.dstore, operand = single_op(1) },
    Opcode.dstore_2 = SimpleInstruction { opcode = Opcode.dstore, operand = single_op(2) },
    Opcode.dstore_3 = SimpleInstruction { opcode = Opcode.dstore, operand = single_op(3) },

    Opcode.dload_0 = SimpleInstruction { opcode = Opcode.dload, operand = single_op(0) },
    Opcode.dload_1 = SimpleInstruction { opcode = Opcode.dload, operand = single_op(1) },
    Opcode.dload_2 = SimpleInstruction { opcode = Opcode.dload, operand = single_op(2) },
    Opcode.dload_3 = SimpleInstruction { opcode = Opcode.dload, operand = single_op(3) },

    Opcode.dconst_0 = SimpleInstruction { opcode = Opcode.dconst_0, operand = nil },
    Opcode.dconst_1 = SimpleInstruction { opcode = Opcode.dconst_1, operand = nil },
    
    Opcode.lconst_0 = SimpleInstruction { opcode = Opcode.lconst_0, operand = nil },
    Opcode.lconst_1 = SimpleInstruction { opcode = Opcode.lconst_1, operand = nil },
    
    Opcode.fconst_0 = SimpleInstruction { opcode = Opcode.fconst_0, operand = nil },
    Opcode.fconst_1 = SimpleInstruction { opcode = Opcode.fconst_1, operand = nil },
    Opcode.fconst_2 = SimpleInstruction { opcode = Opcode.fconst_2, operand = nil },


}
delete_class :: proc(using class: ClassFile) {
    if constant_pool != nil {
        for const in constant_pool {
            if utf8, isutf8 := const.(UTF8Info); isutf8 {
                delete(utf8.str)
            } 
        }
        delete(constant_pool)
    }
    if interfaces != nil {
        delete(interfaces)
    }
    if fields != nil {
        for fld in fields {
            if fld.attributes != nil {
                for attr in fld.attributes {
                    delete_attr(attr)
                } 
                delete(fld.attributes)
            }
        }
        delete(fields)
    }
    if methods != nil {
        for method in methods {
            if method.attributes != nil {
                for attr in method.attributes {
                    delete_attr(attr)
                } 
                delete(method.attributes)
            }
            if method.bytecode != nil {
                codeattr := method.bytecode.(CodeAttribute)
                delete(codeattr.code)
                delete(codeattr.exception_table)
                for attr in codeattr.attributes {
                    delete_attr(attr)
                }
                delete(codeattr.attributes)

            }
        }
        delete(methods)
    }
    if attributes != nil {
        for attr in attributes {
            delete_attr(attr)
        }
        delete(attributes)
    }
}
read_class_file :: proc(bytes: []u8) -> shared.Result(ClassFile, string) {
    using shared
    reader := Reader { bytes = bytes, position = 0 }
    class := ClassFile {}
    result := Ok(ClassFile, string, class)
    defer if result.is_err {
        delete_class(class)
    }
    magic := read_u32_be(&reader)
    if magic == nil || magic.(u32) != 0xCAFEBABE {
        return Err(ClassFile, string, "Invalid class file") 
    }
    minor := read_u16_be(&reader)
    if minor == nil {
        return Err(ClassFile, string, "Invalid class file")
    }
    major := read_u16_be(&reader)
    if major == nil {
        return Err(ClassFile, string, "Invalid class file")
    }
    class.minor_version = minor.(u16)
    class.major_version = major.(u16)
    if class.major_version > JAVA_VERSION {
        return Err(ClassFile, string, "Unsupported java version. Expected <= Java 8")
    }
    constcount := read_u16_be(&reader)
    if constcount == nil {
        return Err(ClassFile, string, "Invalid class file")
    }
    class.constant_pool = make([]ConstantPoolInfo, constcount.(u16) - 1)
    i: u16 = 0
    for i < constcount.(u16) - 1 {
        b := read_byte(&reader) 
        if b == nil {
            result = Err(ClassFile, string, "Invalid class file")
			return result 
        }
        switch b.(u8) {
            case 3:
                value := read_u32_be(&reader)
                if value == nil {
                    result = Err(ClassFile, string, "Invalid class file")
					return result 
                }
                class.constant_pool[i] = IntegerInfo { value = transmute(i32)value.(u32) }
            case 4:
                value := read_u32_be(&reader)
                if value == nil {
                    result = Err(ClassFile, string, "Invalid class file")
					return result 
                }
                class.constant_pool[i] = FloatInfo { value = transmute(f32)value.(u32) }
            case 5:
                value := read_u64_be(&reader)
                if value == nil {
                    result = Err(ClassFile, string, "Invalid class file")
					return result 
                }
                class.constant_pool[i] = LongInfo { value = transmute(i64)value.(u64) }
                class.constant_pool[i + 1] = StoopitJava8ByteConstantTakeTwoPlacesInConstantPool {} 
                i += 1
            case 6:
                value := read_u64_be(&reader)
                if value == nil {
                    result = Err(ClassFile, string, "Invalid class file")
					return result 
                }
                class.constant_pool[i] = DoubleInfo { value = transmute(f64)value.(u64) }
                class.constant_pool[i + 1] = StoopitJava8ByteConstantTakeTwoPlacesInConstantPool {} 
                i += 1
            case 9:
                class_index := read_u16_be(&reader)
                if class_index == nil {
                    result = Err(ClassFile, string, "Invalid class file")
					return result 
                }
                name_and_type_index := read_u16_be(&reader) 
                if name_and_type_index == nil {
                    result = Err(ClassFile, string, "Invalid class file")
					return result 
                }
                fld := FieldRefInfo { class_index = class_index.(u16), name_and_type_index = name_and_type_index.(u16) }
                class.constant_pool[i] = fld 
            case 10:
                class_index := read_u16_be(&reader)
                if class_index == nil {
                    result = Err(ClassFile, string, "Invalid class file")
					return result 
                }
                name_and_type_index := read_u16_be(&reader) 
                if name_and_type_index == nil {
                    result = Err(ClassFile, string, "Invalid class file")
					return result 
                }
                method := MethodRefInfo { class_index = class_index.(u16), name_and_type_index = name_and_type_index.(u16) }
                class.constant_pool[i] = method 
            case 11:
                class_index := read_u16_be(&reader)
                if class_index == nil {
                    result = Err(ClassFile, string, "Invalid class file")
					return result 
                }
                name_and_type_index := read_u16_be(&reader) 
                if name_and_type_index == nil {
                    result = Err(ClassFile, string, "Invalid class file")
					return result 
                }
                method := InterfaceMethodRefInfo { class_index = class_index.(u16), name_and_type_index = name_and_type_index.(u16) }
                class.constant_pool[i] = method 
            case 8:
                string_index := read_u16_be(&reader)
                if string_index == nil {
                    result = Err(ClassFile, string, "Invalid class file")
					return result 
                }
                class.constant_pool[i] = StringInfo { string_index = string_index.(u16) }
            case 7:
                name_index := read_u16_be(&reader)
                if name_index == nil {
                    result = Err(ClassFile, string, "Invalid class file")
					return result 
                }
                class.constant_pool[i] = ClassInfo { name_index = name_index.(u16) }
            case 12:
                name_index := read_u16_be(&reader)
                if name_index == nil {
                    result = Err(ClassFile, string, "Invalid class file")
					return result 
                }
                descriptor_index := read_u16_be(&reader) 
                if descriptor_index == nil {
                    result = Err(ClassFile, string, "Invalid class file")
					return result 
                }
                nm := NameAndTypeInfo { name_index = name_index.(u16), descriptor_index = descriptor_index.(u16) }
                class.constant_pool[i] = nm 
            case 15:
                ref_kind := read_byte (&reader)
                if ref_kind == nil {
                    result = Err(ClassFile, string, "Invalid class file")
					return result 
                }
                reference_index := read_u16_be(&reader) 
                if reference_index == nil {
                    result = Err(ClassFile, string, "Invalid class file")
					return result 
                }
                methodhandle := MethodHandleInfo { reference_kind = cast(BytecodeBehaivour)ref_kind.(u8), reference_index = reference_index.(u16) }
                class.constant_pool[i] = methodhandle 
            case 1:
                length := read_u16_be(&reader)
                if length == nil {
                    result = Err(ClassFile, string, "Invalid class file") 
					return result 
                }
                utf8bytes:[]u8 = make([]u8, length.(u16))
                defer delete(utf8bytes)
                for i in 0..<length.(u16) {
                    b = read_byte(&reader)
                    if b == nil {
                        result = Err(ClassFile, string, "Invalid class file") 
					    return result 
                    }
                    utf8bytes[i] = b.(u8)
                }
                class.constant_pool[i] = UTF8Info { str = strings.clone_from_bytes(utf8bytes) }
            case: 
                fmt.println(b)
                panic("")

        }
        i += 1
    }
    access_flags := read_u16_be(&reader)
    if access_flags == nil {
        result = Err(ClassFile, string, "Invalid class file")
		return result 
    }
    class.access_flags = transmute(AccessFlags)access_flags.(u16)

    this_class := read_u16_be(&reader)
    if this_class == nil {
        result = Err(ClassFile, string, "Invalid class file")
		return result 
    }
    class.this_class = this_class.(u16)
    super_class := read_u16_be(&reader)
    if super_class == nil {
        result = Err(ClassFile, string, "Invalid class file")
		return result 
    }
    class.super_class = super_class.(u16)
    interface_count := read_u16_be(&reader)
    if interface_count == nil {
        result = Err(ClassFile, string, "Invalid class file")
		return result 
    }
    class.interfaces = make([]u16, interface_count.(u16))
    for i in 0..<interface_count.(u16) {
        interface := read_u16_be(&reader)
        if interface == nil {
            result = Err(ClassFile, string, "Invalid class file")
			return result 
        }
        class.interfaces[i] = interface.(u16)
    }
    field_count := read_u16_be(&reader)
    if field_count == nil {
        result = Err(ClassFile, string, "Invalid class file")
		return result 
    }

    class.fields = make([]FieldInfo, field_count.(u16))
    for f in 0..<field_count.(u16) {
        access_flags := read_u16_be(&reader)
        if access_flags == nil {
            result = Err(ClassFile, string, "Invalid class file")
			return result 
        }
        name_index := read_u16_be(&reader)
        if name_index == nil {
            result = Err(ClassFile, string, "Invalid class file")
			return result 
        }
        descriptor_index := read_u16_be(&reader)
        if descriptor_index == nil {
            result = Err(ClassFile, string, "Invalid class file")
			return result 
        }
        attribute_count := read_u16_be(&reader)
        if attribute_count == nil {
            result = Err(ClassFile, string, "Invalid class file")
			return result 
        }
        attributes := make([]AttributeInfo, attribute_count.(u16))
        for attri in 0..<attribute_count.(u16) {
            attr := read_attr(&reader)
            if attr == nil {
                result = Err(ClassFile, string, "Invalid class file")
				return result 
            }
            attributes[attri] = attr.(AttributeInfo)
        }
        class.fields[f] = FieldInfo {
            access_flags = transmute(AccessFlags)access_flags.(u16),
            name_index = name_index.(u16),
            descriptor_index = descriptor_index.(u16),
            attributes = attributes,
        }
    }
    method_count := read_u16_be(&reader)
    if method_count == nil {
        result = Err(ClassFile, string, "Invalid class file")
		return result 
    }
    class.methods = make([]MethodInfo, method_count.(u16))
    for mi in 0..<method_count.(u16) {
        access_flags := read_u16_be(&reader)    
        if access_flags == nil {
            result = Err(ClassFile, string, "Invalid class file")
			return result 
        }
        name_index := read_u16_be(&reader)    
        if name_index == nil {
            result = Err(ClassFile, string, "Invalid class file")
			return result 
        }
        descriptor_index := read_u16_be(&reader)    
        if descriptor_index == nil {
            result = Err(ClassFile, string, "Invalid class file")
			return result 
        }

        attribute_count := read_u16_be(&reader)    
        if attribute_count == nil {
            result = Err(ClassFile, string, "Invalid class file")
			return result 
        }
        attributes := make([]AttributeInfo, attribute_count.(u16))
        for attri in 0..<attribute_count.(u16) {
            attr := read_attr(&reader)
            if attr == nil {
                result = Err(ClassFile, string, "Invalid class file")
			    return result 
            }
            attributes[attri] = attr.(AttributeInfo)
        }
        class.methods[mi] = MethodInfo {
            access_flags = transmute(AccessFlags)access_flags.(u16),
            name_index = name_index.(u16),
            descriptor_index = descriptor_index.(u16),
            attributes = attributes,
        }
    }
    attr_count := read_u16_be(&reader)
    if attr_count == nil {
        result = Err(ClassFile, string, "Invalid class file")
		return result 
    }
    class.attributes = make([]AttributeInfo, attr_count.(u16))
    for attri in 0..<attr_count.(u16) {
        attr := read_attr(&reader)
        if attr == nil {
            result = Err(ClassFile, string, "Invalid class file")
			return result 
        }
        class.attributes[attri] = attr.(AttributeInfo)
    }

    for method,i in class.methods {
        codeattr := find_attr(&class, method.attributes, "Code")
        if codeattr != nil {
            code_reader := Reader {
                bytes = codeattr.(AttributeInfo).info,
                position = 0,
            }
            max_stack := read_u16_be(&code_reader)
            if max_stack == nil {
                result = Err(ClassFile, string, "Invalid code attribute")
                return result 
            }
            max_locals := read_u16_be(&code_reader)
            if max_locals == nil {
                result = Err(ClassFile, string, "Invalid code attribute")
                return result 
            }
            code_length := read_u32_be(&code_reader)
            if code_length == nil {
                result = Err(ClassFile, string, "Invalid code attribute")
                return result 
            }
            if len(code_reader.bytes) - code_reader.position < cast(int)code_length.(u32) {
                result = Err(ClassFile, string, "Invalid code attribute")
                return result 
            }
            code_bytes := code_reader.bytes[code_reader.position:code_reader.position + cast(int)code_length.(u32)]
            code_reader.position += cast(int)code_length.(u32)
            instructions := parse_bytecode(&class, code_bytes)
            if instructions.is_err {
                result = Err(ClassFile, string, instructions.error.(string))
                return result 
            }
            exception_table_length := read_u16_be(&code_reader)
            if exception_table_length == nil {
                result = Err(ClassFile, string, "Invalid code attribute")
                return result 
            }
            exception_table := make([]ExceptionInfo, exception_table_length.(u16))
            for i in 0..<len(exception_table) {
                start_pc := read_u16_be(&code_reader)
                if start_pc == nil {
                    result = Err(ClassFile, string, "Invalid code attribute")
                    return result 
                }
                end_pc := read_u16_be(&code_reader)
                if end_pc == nil {
                    result = Err(ClassFile, string, "Invalid code attribute")
                    return result 
                }
                handler_pc := read_u16_be(&code_reader)
                if handler_pc == nil {
                    result = Err(ClassFile, string, "Invalid code attribute")
                    return result 
                }
                catch_type := read_u16_be(&code_reader)
                if catch_type == nil {
                    result = Err(ClassFile, string, "Invalid code attribute")
                    return result 
                }
                exception_table[i] = ExceptionInfo {
                    start_pc = start_pc.(u16),
                    end_pc = end_pc.(u16),
                    handler_pc = handler_pc.(u16),
                    catch_type = catch_type.(u16),
                }
            }
                
            attr_count := read_u16_be(&code_reader)
            if attr_count == nil {
                result = Err(ClassFile, string, "Invalid class file")
                return result 
            }
            code_attributes := make([]AttributeInfo, attr_count.(u16))
            for attri in 0..<attr_count.(u16) {
                attr := read_attr(&code_reader)
                if attr == nil {
                    result = Err(ClassFile, string, "Invalid class file")
                    return result 
                }
                code_attributes[attri] = attr.(AttributeInfo)
            }
            class.methods[i].bytecode = CodeAttribute {
                max_stack = max_stack.(u16),
                max_locals = max_locals.(u16),
                code = instructions.value.([]Instruction),
                exception_table = exception_table,
                attributes = code_attributes,
            }
        }
    }

    return Ok(ClassFile, string, class)
}
parse_bytecode :: proc(class: ^ClassFile, bytes: []u8) -> shared.Result([]Instruction, string) {
    instructions := make([dynamic]Instruction)
    i := 0
    next_is_wide := false
    result := shared.Ok([]Instruction, string, nil)
    defer if result.is_err {
        delete(instructions)
    }
    for i < len(bytes) {
        opcode := cast(Opcode)bytes[i]
        switch opcode {
            case .istore, .iload, 
                .fstore, .fload,
                .dstore, .dload,
                .lstore, .lload,
                .astore, .aload,
                .iinc:
                if opcode == .iinc {
                    size := 2
                    if next_is_wide {
                        size = 4
                    }
                    if i + size >= len(bytes) {
                        result = shared.Err([]Instruction, string, "Invalid bytecode")
                        return result
                    }
                    index := 0
                    count := 0
                    if next_is_wide {
                        index = ((cast(int)bytes[i + 1]) << 8) | cast(int)bytes[i + 2] 
                        count = ((cast(int)bytes[i + 3]) << 8) | cast(int)bytes[i + 4] 
                    }
                    else {
                        index = cast(int)bytes[i + 1]
                        count = cast(int)bytes[i + 2]
                    }
                    append(&instructions, SimpleInstruction { offset = i, opcode = opcode, operand = two_op(index, count)})
                    i += size
                }
                else {
                    size := 1
                    if next_is_wide {
                        size = 2
                    }
                    if i + size >= len(bytes) {
                        result = shared.Err([]Instruction, string, "Invalid bytecode")
                        return result
                    }
                    index := 0
                    if next_is_wide {
                        index = (cast(int)bytes[i + 1] << 8) | cast(int)bytes[i + 2] 
                    }
                    else {
                        index = cast(int)bytes[i + 1]
                    }
                    append(&instructions, SimpleInstruction { offset = i, opcode = opcode, operand = single_op(index)})
                    i += 2
                }
                next_is_wide = false

            case .bipush, .ldc, 
                .newarray:
                if i + 1 >= len(bytes) {
                    result = shared.Err([]Instruction, string, "Invalid bytecode")
                    return result
                }
                else if next_is_wide {
                    result = shared.Err([]Instruction, string, "Invalid opcode after wide prefix")
                    return result
                }
                append(&instructions, SimpleInstruction { offset = i, opcode = opcode, operand = single_op_b(bytes[i + 1]) })
                i += 1
            case .aload_0, .aload_1, .aload_2, .aload_3,
                 .istore_0, .istore_1, .istore_2, .istore_3,
                 .astore_0, .astore_1, .astore_2, .astore_3,
                .lstore_0, .lstore_1, .lstore_2, .lstore_3,
                 .iload_0, .iload_1, .iload_2, .iload_3,
                 .lload_0, .lload_1, .lload_2, .lload_3,
                 .dstore_0, .dstore_1, .dstore_2, .dstore_3,
                 .dload_0, .dload_1, .dload_2, .dload_3,
                 .iconst_m1, .iconst_0, .iconst_1, .iconst_2, .iconst_3, .iconst_4, .iconst_5,
                 .dconst_0, .dconst_1,
                 .lconst_0, .lconst_1,
                 .fconst_0, .fconst_1, .fconst_2,
                 .fstore_0, .fstore_1, .fstore_2, .fstore_3,
                 .fload_0, .fload_1, .fload_2, .fload_3:
                 
                if next_is_wide {
                    result = shared.Err([]Instruction, string, "Invalid opcode after wide prefix")
                    return result
                }
                instr, ok := hardcoded_opcodes[opcode]
                if !ok {
                    panic("")
                }
                instr.offset = i
                append(&instructions,instr) 
            case .invokespecial, .putfield, .putstatic, .ldc_w, .ldc2_w, .getstatic, .getfield, .invokevirtual, .invokestatic,
                .sipush, .anewarray,
                .checkcast, .instanceof, .new:
                if i + 2 >= len(bytes) {
                    result = shared.Err([]Instruction, string, "Invalid bytecode")
                    return result
                }
                else if next_is_wide {
                    result = shared.Err([]Instruction, string, "Invalid opcode after wide prefix")
                    return result
                }
                value: u16 = cast(u16)bytes[i + 2] | (cast(u16)bytes[i + 1] << 8) 
                append(&instructions, SimpleInstruction { offset = i, opcode = opcode, operand = single_op_s(value)})
                i += 2
                case .ifeq, .ifge, .ifgt, .ifle, .iflt, .ifne, .ifnull, .ifnonnull, .if_acmpeq, .if_acmpne, .if_icmpeq, .if_icmpge, .if_icmpgt, .if_icmple, .if_icmplt, .if_icmpne:
                    if i + 2 >= len(bytes) {
                        result = shared.Err([]Instruction, string, "Invalid bytecode")
                        return result
                    }
                    else if next_is_wide {
                        result = shared.Err([]Instruction, string, "Invalid opcode after wide prefix")
                        return result
                    }
                    value: int = cast(int)(transmute(i16)(cast(u16)bytes[i + 2] | (cast(u16)bytes[i + 1] << 8))) 
                    append(&instructions, SimpleInstruction { offset = i, opcode = opcode, operand = single_op(value + i)})
                    i += 2
                    
            case .multianewarray:
                if i + 3 >= len(bytes) {
                    result = shared.Err([]Instruction, string, "Invalid bytecode")
                    return result
                }
                else if next_is_wide {
                    result = shared.Err([]Instruction, string, "Invalid opcode after wide prefix")
                    return result
                }
                value: u16 = cast(u16)bytes[i + 2] | (cast(u16)bytes[i + 1] << 8) 
                dimensions := bytes[i + 3]
                append(&instructions, SimpleInstruction { offset = i, opcode = opcode, operand = two_op(cast(int)value, cast(int)dimensions) })
                i += 3

            case .invokeinterface:
                if i + 4 >= len(bytes) {
                    result = shared.Err([]Instruction, string, "Invalid bytecode")
                    return result
                }
                else if next_is_wide {
                    result = shared.Err([]Instruction, string, "Invalid opcode after wide prefix")
                    return result
                }
                value: u16 = cast(u16)bytes[i + 2] | (cast(u16)bytes[i + 1] << 8) 
                count := bytes[i + 3]
                append(&instructions, SimpleInstruction { offset = i, opcode = opcode, operand = two_op(cast(int)value, cast(int)count) })
                i += 4
            case .invokedynamic:
                if i + 4 >= len(bytes) {
                    result = shared.Err([]Instruction, string, "Invalid bytecode")
                    return result
                }
                else if next_is_wide {
                    result = shared.Err([]Instruction, string, "Invalid opcode after wide prefix")
                    return result
                }
                value: u16 = cast(u16)bytes[i + 2] | (cast(u16)bytes[i + 1] << 8) 
                append(&instructions, SimpleInstruction { offset = i, opcode = opcode, operand = single_op(cast(int)value) })
                i += 4

                
                
            case .nop, .pop, .pop2, .dup, .dup2, .dup_x1, .dup_x2, .dup2_x1, .dup2_x2, 
                .arraylength, .aconst_null, 
                ._return, .ireturn, .dreturn, .lreturn, .freturn, .areturn, 
                .isub, .fsub, .dsub, .lsub,
                .iadd, .fadd, .dadd, .ladd,
                .irem, .frem, .drem, .lrem,
                .idiv, .fdiv, .ddiv, .ldiv,
                .imul, .fmul, .dmul, .lmul,
                .ineg, .fneg, .dneg, .lneg,
                .iand, .land,
                .ior, .lor,
                .ixor, .lxor,
                .ishl, .lshl,
                .ishr, .lshr,
                .iushr, .lushr,
                .lcmp,
                .aaload, .aastore, .caload, .castore, .baload, .bastore, .iaload, .iastore, .laload, .lastore, .faload, .fastore, .daload, .dastore, .saload, .sastore,
                .d2f, .d2i, .d2l,
                .f2d, .f2i, .f2l,
                .i2b, .i2c, .i2d, .i2f, .i2l, .i2s,
                .l2d, .l2f, .l2i,
                .dcmpg, .dcmpl, .fcmpg, .fcmpl,
                .athrow, .swap, .breakpoint,
                .monitorexit, .monitorenter:
                if next_is_wide {
                    result = shared.Err([]Instruction, string, "Invalid opcode after wide prefix")
                    return result
                }
                append(&instructions, SimpleInstruction { offset = i, opcode = opcode, operand = nil})
            case .goto:
                if i + 2 >= len(bytes) {
                    result = shared.Err([]Instruction, string, "Invalid bytecode")
                    return result
                }
                else if next_is_wide {
                    result = shared.Err([]Instruction, string, "Invalid opcode after wide prefix")
                    return result
                }
                value: int = cast(int)(transmute(i16)((cast(u16)bytes[i+1] << 8) | cast(u16)(bytes[i+2])))
                append(&instructions, SimpleInstruction { offset = i, opcode = opcode, operand = single_op(value + i)})
                i += 2
            case .goto_w:
                if i + 4 >= len(bytes) {
                    result = shared.Err([]Instruction, string, "Invalid bytecode")
                    return result
                }
                else if next_is_wide {
                    result = shared.Err([]Instruction, string, "Invalid opcode after wide prefix")
                    return result
                }
                branch := cast(int)transmute(i32)((cast(u32)bytes[i + 1] << 24) | (cast(u32)bytes[i + 2] << 16) | (cast(u32)bytes[i + 3] << 8) | (cast(u32)bytes[i + 4]))
                append(&instructions, SimpleInstruction {offset = i, opcode = opcode, operand = single_op(branch + i)})
            case .wide:
                if next_is_wide {
                    result = shared.Err([]Instruction, string, "Invalid opcode after wide prefix")
                    return result
                }
                next_is_wide = true
            case .jsr_depr, .ret_depr, .jsr_w_depr:
                panic("deprecated")
            case .impdep1, .impdep2: 
                panic("should not appear")
            case .tableswitch:
                start := i
                if i % 4 != 0 {
                    i += 4 - i%4
                }
                table_reader := Reader { bytes = bytes, position = i }
                default := read_u32_be(&table_reader)
                if default == nil {
                    result = shared.Err([]Instruction, string, "Invalid bytecode")
                    return result
                }
                low := read_u32_be(&table_reader)
                if low == nil {
                    result = shared.Err([]Instruction, string, "Invalid bytecode")
                    return result
                }
                high := read_u32_be(&table_reader)
                if high == nil {
                    result = shared.Err([]Instruction, string, "Invalid bytecode")
                    return result
                }
                table := TableSwitch {}
                table.default = cast(int)default.(u32) + start
                table.low = cast(int)low.(u32)
                table.high = cast(int)high.(u32)
                table.offsets = make([]int, table.high - table.low + 1)
                for i in table.low..=table.high {
                    off := read_u32_be(&table_reader)
                    if off == nil {
                        result = shared.Err([]Instruction, string, "Invalid bytecode")
                        return result
                    }
                    table.offsets[i - table.low] = cast(int)off.(u32) + start
                    
                }
                i = table_reader.position - 1
                table.offset = start
                table.opcode = Opcode.tableswitch
                append(&instructions, table)
            case .lookupswitch:
                fmt.println("Unimplemented", opcode)
                panic("")
        }
        i += 1
    }
    return shared.Ok([]Instruction, string, instructions[:])    
}
resolve_class_name :: proc(class: ^ClassFile, index: u16) -> Maybe(string) {
    if cast(int)index <= len(class.constant_pool) && index != 0 {
        cl, isok := class.constant_pool[index - 1].(ClassInfo)
        if isok {
            return resolve_utf8(class, cl.name_index)
        }
    }
    return nil
}
resolve_utf8 :: proc(class: ^ClassFile, index: u16) -> Maybe(string) {
    if cast(int)index <= len(class.constant_pool) && index != 0 {
        utf8, isutf8 := class.constant_pool[index - 1].(UTF8Info)
        if isutf8 {
            return utf8.str
        }
    }
    return nil
}
find_attr :: proc(class: ^ClassFile, attrs: []AttributeInfo, name: string) -> Maybe(AttributeInfo) {
    for attr in attrs {
        if resolve_utf8(class, attr.name_index) == name {
            return attr
        }
    }
    return nil
}
read_attr :: proc(reader: ^Reader) -> Maybe(AttributeInfo) {
    attr_name_index := read_u16_be(reader)
    if attr_name_index == nil {
        return nil
    }
    attr_length := read_u32_be(reader)
    if attr_length == nil {
        return nil
    }
    attr_data := make([]u8, attr_length.(u32))
    for b in 0..<attr_length.(u32) {
        byte := read_byte(reader)
        if byte == nil {
            delete(attr_data)
            return nil
        }
        attr_data[b] = byte.(u8)
    }
    return AttributeInfo {
        name_index = attr_name_index.(u16),
        info = attr_data,
    }
}
print_class_info :: proc(class: ClassFile) {

    for info,i in class.constant_pool {
        #partial switch in info {
            case StringInfo:
                utf := class.constant_pool[info.(StringInfo).string_index-1].(UTF8Info)
                fmt.printf("#%i string: \"%s\"\n", i + 1, utf.str)
            case UTF8Info:
                fmt.printf("#%i utf8: \"%s\"\n", i + 1, info.(UTF8Info).str)
            case MethodRefInfo:
                class_name := class.constant_pool[class.constant_pool[info.(MethodRefInfo).class_index-1].(ClassInfo).name_index-1].(UTF8Info)
                name_and_type := class.constant_pool[info.(MethodRefInfo).name_and_type_index-1].(NameAndTypeInfo)
                name := class.constant_pool[name_and_type.name_index - 1].(UTF8Info)
                type := class.constant_pool[name_and_type.descriptor_index - 1].(UTF8Info)
                fmt.printf("#%i method: %s.%s:%s\n", i + 1, class_name.str, name.str, type.str)
            case ClassInfo:
                name := class.constant_pool[info.(ClassInfo).name_index-1].(UTF8Info).str
                fmt.printf("#%i class: %s\n", i + 1, name)
            case NameAndTypeInfo:
                name := class.constant_pool[info.(NameAndTypeInfo).name_index - 1].(UTF8Info)
                type := class.constant_pool[info.(NameAndTypeInfo).descriptor_index - 1].(UTF8Info)
                fmt.printf("#%i name_and_type: %s:%s\n", i + 1, name.str, type.str)
            case FieldRefInfo:
                class_name := class.constant_pool[class.constant_pool[info.(FieldRefInfo).class_index-1].(ClassInfo).name_index-1].(UTF8Info)
                name_and_type := class.constant_pool[info.(FieldRefInfo).name_and_type_index-1].(NameAndTypeInfo)
                name := class.constant_pool[name_and_type.name_index - 1].(UTF8Info)
                type := class.constant_pool[name_and_type.descriptor_index - 1].(UTF8Info)
                fmt.printf("#%i field: %s.%s:%s\n", i + 1, class_name.str, name.str, type.str)
            case IntegerInfo:
                fmt.printf("#%i int: %i\n",i+1, info.(IntegerInfo).value)
            case FloatInfo:
                fmt.printf("#%i float: %f\n",i+1, info.(FloatInfo).value)
            case LongInfo:
                fmt.printf("#%i long: %i\n",i+1, info.(LongInfo).value)
            case DoubleInfo:
                fmt.printf("#%i double: %f\n",i+1, info.(DoubleInfo).value)
            case InterfaceMethodRefInfo:
                class_name := class.constant_pool[class.constant_pool[info.(InterfaceMethodRefInfo).class_index - 1].(ClassInfo).name_index - 1].(UTF8Info)
                name_and_type := class.constant_pool[info.(InterfaceMethodRefInfo).name_and_type_index-1].(NameAndTypeInfo)
                name := class.constant_pool[name_and_type.name_index - 1].(UTF8Info)
                type := class.constant_pool[name_and_type.descriptor_index - 1].(UTF8Info)

                fmt.printf("#%i interface method: %s.%s:%s", i + 1, class_name.str, name.str, type.str)
            case StoopitJava8ByteConstantTakeTwoPlacesInConstantPool:
            case:
                fmt.println(info)
                panic("")
        }
    }
    fmt.printf("%i.%i\n", class.major_version, class.minor_version)
    fmt.printf("Access flags: ")
    print_flags(class.access_flags)
    fmt.println()
    fmt.printf("This class: %s\n", class.constant_pool[class.constant_pool[class.this_class - 1].(ClassInfo).name_index - 1].(UTF8Info).str)
    if cast(int)class.super_class <= len(class.constant_pool) && class.super_class != 0 {
        fmt.printf("Super class: %s\n", class.constant_pool[class.constant_pool[class.super_class - 1].(ClassInfo).name_index - 1].(UTF8Info).str)
    }
    fmt.printf("Interface count: %i\n", len(class.interfaces))
    for interface, i in class.interfaces {
        fmt.printf("#%i: %s\n", i, class.constant_pool[class.constant_pool[interface - 1].(ClassInfo).name_index - 1].(UTF8Info).str)
    }
    fmt.printf("Field count: %i\n", len(class.fields))
    for fld in class.fields {
        print_flags(fld.access_flags)
        fmt.printf(" %s %s\n", class.constant_pool[fld.descriptor_index - 1].(UTF8Info).str, class.constant_pool[fld.name_index - 1].(UTF8Info).str)
    }
    fmt.printf("Method count: %i\n", len(class.methods))
    for method in class.methods {
        print_flags(method.access_flags)
        fmt.printf(" %s %s\n", class.constant_pool[method.descriptor_index - 1].(UTF8Info).str, class.constant_pool[method.name_index - 1].(UTF8Info).str)
        if method.bytecode != nil {
            code := method.bytecode.(CodeAttribute)
            fmt.printf("max_stack: %i max_locals: %i\n", code.max_stack, code.max_locals)
            for instr in code.code {
                switch in instr {
                    case SimpleInstruction: {
                        fmt.printf("\t%3i: %s ",instr.(SimpleInstruction).offset, instr.(SimpleInstruction).opcode) 
                        switch in instr.(SimpleInstruction).operand {
                            case OneOperand: {
                                fmt.println(instr.(SimpleInstruction).operand.(OneOperand).op)
                            }
                            case TwoOperands: {
                                ops := instr.(SimpleInstruction).operand.(TwoOperands)
                                fmt.printf("%i %i\n", ops.op1, ops.op2)
                            }
                            case nil:
                                fmt.println()
                        }
                    } 
                    case TableSwitch:
                        table := instr.(TableSwitch)
                        fmt.printf("\t%3i: %s low: %i high: %i\n", table.offset, table.opcode, table.low, table.high) 
                        for off, i in table.offsets {
                            fmt.printf("\t\t%7i: %i\n", i + table.low, off) 
                        }
                        fmt.printf("\t\tdefault: %i\n", table.default) 


                }
            }
        }
    }

    fmt.println(class.attributes)
}
main :: proc() {
    args := os.args
    if len(args) != 2 {
        print_usage()
        os.exit(0)
    }
    classfilename := args[1]
    if !os.exists(classfilename) {
        error("File %s does not exists", classfilename)
    }
    bytes, ok := os.read_entire_file(classfilename)
    if !ok {
        error("Failed to read class file")
    }
    classm := (read_class_file(bytes))
    if classm.is_err {
        error(classm.error.(string)) 
    }
    class := classm.value.(ClassFile)
    print_class_info(class)

}
