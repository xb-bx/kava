package classparser
import "core:fmt"
import "core:os"
import "core:strings"
import "kava:shared"


JAVA_VERSION :: 52 // Java 8


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
Class :: struct {
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
delete_class :: proc(using class: Class) {
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
read_class_file :: proc(bytes: []u8) -> shared.Result(Class, string) {
    using shared
    reader := Reader { bytes = bytes, position = 0 }
    class := Class {}
    result := Ok(Class, string, class)
    defer if result.is_err {
        delete_class(class)
    }
    magic := read_u32_be(&reader)
    if magic == nil || magic.(u32) != 0xCAFEBABE {
        return Err(Class, string, "Invalid class file") 
    }
    minor := read_u16_be(&reader)
    if minor == nil {
        return Err(Class, string, "Invalid class file")
    }
    major := read_u16_be(&reader)
    if major == nil {
        return Err(Class, string, "Invalid class file")
    }
    class.minor_version = minor.(u16)
    class.major_version = major.(u16)
    if class.major_version > JAVA_VERSION {
        return Err(Class, string, "Unsupported java version. Expected <= Java 8")
    }
    constcount := read_u16_be(&reader)
    if constcount == nil {
        return Err(Class, string, "Invalid class file")
    }
    class.constant_pool = make([]ConstantPoolInfo, constcount.(u16) - 1)
    i: u16 = 0
    for i < constcount.(u16) - 1 {
        b := read_byte(&reader) 
        if b == nil {
            result = Err(Class, string, "Invalid class file")
			return result 
        }
        switch b.(u8) {
            case 3:
                value := read_u32_be(&reader)
                if value == nil {
                    result = Err(Class, string, "Invalid class file")
					return result 
                }
                class.constant_pool[i] = IntegerInfo { value = transmute(i32)value.(u32) }
            case 4:
                value := read_u32_be(&reader)
                if value == nil {
                    result = Err(Class, string, "Invalid class file")
					return result 
                }
                class.constant_pool[i] = FloatInfo { value = transmute(f32)value.(u32) }
            case 5:
                value := read_u64_be(&reader)
                if value == nil {
                    result = Err(Class, string, "Invalid class file")
					return result 
                }
                class.constant_pool[i] = LongInfo { value = transmute(i64)value.(u64) }
                class.constant_pool[i + 1] = StoopitJava8ByteConstantTakeTwoPlacesInConstantPool {} 
                i += 1
            case 6:
                value := read_u64_be(&reader)
                if value == nil {
                    result = Err(Class, string, "Invalid class file")
					return result 
                }
                class.constant_pool[i] = DoubleInfo { value = transmute(f64)value.(u64) }
                class.constant_pool[i + 1] = StoopitJava8ByteConstantTakeTwoPlacesInConstantPool {} 
                i += 1
            case 9:
                class_index := read_u16_be(&reader)
                if class_index == nil {
                    result = Err(Class, string, "Invalid class file")
					return result 
                }
                name_and_type_index := read_u16_be(&reader) 
                if name_and_type_index == nil {
                    result = Err(Class, string, "Invalid class file")
					return result 
                }
                fld := FieldRefInfo { class_index = class_index.(u16), name_and_type_index = name_and_type_index.(u16) }
                class.constant_pool[i] = fld 
            case 10:
                class_index := read_u16_be(&reader)
                if class_index == nil {
                    result = Err(Class, string, "Invalid class file")
					return result 
                }
                name_and_type_index := read_u16_be(&reader) 
                if name_and_type_index == nil {
                    result = Err(Class, string, "Invalid class file")
					return result 
                }
                method := MethodRefInfo { class_index = class_index.(u16), name_and_type_index = name_and_type_index.(u16) }
                class.constant_pool[i] = method 
            case 11:
                class_index := read_u16_be(&reader)
                if class_index == nil {
                    result = Err(Class, string, "Invalid class file")
					return result 
                }
                name_and_type_index := read_u16_be(&reader) 
                if name_and_type_index == nil {
                    result = Err(Class, string, "Invalid class file")
					return result 
                }
                method := InterfaceMethodRefInfo { class_index = class_index.(u16), name_and_type_index = name_and_type_index.(u16) }
                class.constant_pool[i] = method 
            case 8:
                string_index := read_u16_be(&reader)
                if string_index == nil {
                    result = Err(Class, string, "Invalid class file")
					return result 
                }
                class.constant_pool[i] = StringInfo { string_index = string_index.(u16) }
            case 7:
                name_index := read_u16_be(&reader)
                if name_index == nil {
                    result = Err(Class, string, "Invalid class file")
					return result 
                }
                class.constant_pool[i] = ClassInfo { name_index = name_index.(u16) }
            case 12:
                name_index := read_u16_be(&reader)
                if name_index == nil {
                    result = Err(Class, string, "Invalid class file")
					return result 
                }
                descriptor_index := read_u16_be(&reader) 
                if descriptor_index == nil {
                    result = Err(Class, string, "Invalid class file")
					return result 
                }
                nm := NameAndTypeInfo { name_index = name_index.(u16), descriptor_index = descriptor_index.(u16) }
                class.constant_pool[i] = nm 
            case 15:
                ref_kind := read_byte (&reader)
                if ref_kind == nil {
                    result = Err(Class, string, "Invalid class file")
					return result 
                }
                reference_index := read_u16_be(&reader) 
                if reference_index == nil {
                    result = Err(Class, string, "Invalid class file")
					return result 
                }
                methodhandle := MethodHandleInfo { reference_kind = cast(BytecodeBehaivour)ref_kind.(u8), reference_index = reference_index.(u16) }
                class.constant_pool[i] = methodhandle 
            case 1:
                length := read_u16_be(&reader)
                if length == nil {
                    result = Err(Class, string, "Invalid class file") 
					return result 
                }
                utf8bytes:[]u8 = make([]u8, length.(u16))
                defer delete(utf8bytes)
                for i in 0..<length.(u16) {
                    b = read_byte(&reader)
                    if b == nil {
                        result = Err(Class, string, "Invalid class file") 
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
        result = Err(Class, string, "Invalid class file")
		return result 
    }
    class.access_flags = transmute(AccessFlags)access_flags.(u16)

    this_class := read_u16_be(&reader)
    if this_class == nil {
        result = Err(Class, string, "Invalid class file")
		return result 
    }
    class.this_class = this_class.(u16)
    super_class := read_u16_be(&reader)
    if super_class == nil {
        result = Err(Class, string, "Invalid class file")
		return result 
    }
    class.super_class = super_class.(u16)
    interface_count := read_u16_be(&reader)
    if interface_count == nil {
        result = Err(Class, string, "Invalid class file")
		return result 
    }
    class.interfaces = make([]u16, interface_count.(u16))
    for i in 0..<interface_count.(u16) {
        interface := read_u16_be(&reader)
        if interface == nil {
            result = Err(Class, string, "Invalid class file")
			return result 
        }
        class.interfaces[i] = interface.(u16)
    }
    field_count := read_u16_be(&reader)
    if field_count == nil {
        result = Err(Class, string, "Invalid class file")
		return result 
    }

    class.fields = make([]FieldInfo, field_count.(u16))
    for f in 0..<field_count.(u16) {
        access_flags := read_u16_be(&reader)
        if access_flags == nil {
            result = Err(Class, string, "Invalid class file")
			return result 
        }
        name_index := read_u16_be(&reader)
        if name_index == nil {
            result = Err(Class, string, "Invalid class file")
			return result 
        }
        descriptor_index := read_u16_be(&reader)
        if descriptor_index == nil {
            result = Err(Class, string, "Invalid class file")
			return result 
        }
        attribute_count := read_u16_be(&reader)
        if attribute_count == nil {
            result = Err(Class, string, "Invalid class file")
			return result 
        }
        attributes := make([]AttributeInfo, attribute_count.(u16))
        for attri in 0..<attribute_count.(u16) {
            attr := read_attr(&reader)
            if attr == nil {
                result = Err(Class, string, "Invalid class file")
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
        result = Err(Class, string, "Invalid class file")
		return result 
    }
    class.methods = make([]MethodInfo, method_count.(u16))
    for mi in 0..<method_count.(u16) {
        access_flags := read_u16_be(&reader)    
        if access_flags == nil {
            result = Err(Class, string, "Invalid class file")
			return result 
        }
        name_index := read_u16_be(&reader)    
        if name_index == nil {
            result = Err(Class, string, "Invalid class file")
			return result 
        }
        descriptor_index := read_u16_be(&reader)    
        if descriptor_index == nil {
            result = Err(Class, string, "Invalid class file")
			return result 
        }

        attribute_count := read_u16_be(&reader)    
        if attribute_count == nil {
            result = Err(Class, string, "Invalid class file")
			return result 
        }
        attributes := make([]AttributeInfo, attribute_count.(u16))
        for attri in 0..<attribute_count.(u16) {
            attr := read_attr(&reader)
            if attr == nil {
                result = Err(Class, string, "Invalid class file")
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
        result = Err(Class, string, "Invalid class file")
		return result 
    }
    class.attributes = make([]AttributeInfo, attr_count.(u16))
    for attri in 0..<attr_count.(u16) {
        attr := read_attr(&reader)
        if attr == nil {
            result = Err(Class, string, "Invalid class file")
			return result 
        }
        class.attributes[attri] = attr.(AttributeInfo)
    }



    return Ok(Class, string, class)
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
    class := classm.value.(Class)
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
            case StoopitJava8ByteConstantTakeTwoPlacesInConstantPool:
            case:
                fmt.println(info)
                panic("")
        }
    }
    fmt.printf("Access flags: 0x%4X\n", transmute(u16)class.access_flags)
    fmt.printf("This class: %s\n", class.constant_pool[class.constant_pool[class.this_class - 1].(ClassInfo).name_index - 1].(UTF8Info).str)
    fmt.printf("Super class: %s\n", class.constant_pool[class.constant_pool[class.super_class - 1].(ClassInfo).name_index - 1].(UTF8Info).str)
    fmt.printf("Interface count: %i\n", len(class.interfaces))
    for interface, i in class.interfaces {
        fmt.printf("#%i: %s\n", i, class.constant_pool[class.constant_pool[interface - 1].(ClassInfo).name_index - 1].(UTF8Info).str)
    }
    fmt.println(class.fields)
    fmt.println(class.methods)
    fmt.println(class.attributes)
    

}
