from packages.log import LOG

SHORT_TYPES = {
    'V': "void",
    'Z': "boolean",
    'B': "byte",
    'S': "short",
    'C': "char",
    'I': "int",
    'J': "long",
    'F': "float",
    'D': "double",
}
# TYPE_CODES ={
#     'TYPE_HEADER_ITEM':0x0000,
#     'TYPE_STRING_ID_ITEM':0x0001,
#     'TYPE_TYPE_ID_ITEM':0x0002,
#     'TYPE_PROTO_ID_ITEM':0x0003,
#     'TYPE_FIELD_ID_ITEM':0x0004,
#     'TYPE_METHOD_ID_ITEM':0x0005,
#     'TYPE_CLASS_DEF_ITEM':0x0006,
#
#     'TYPE_MAP_LIST':0x1000,
#     'TYPE_TYPE_LIST':0x1001,
#     'TYPE_ANNOTATION_SET_REF_LIST':0x1002,
#     'TYPE_ANNOTATION_SET_ITEM':0x1003,
#
#     'TYPE_CLASS_DATA_ITEM':0x2000,
#     'TYPE_CODE_ITEM':0x2001,
#     'TYPE_STRING_DATA_ITEM':0x2002,
#     'TYPE_DEBUG_INFO_ITEM':0x2003,
#     'TYPE_ANNOTATION_ITEM':0x2004,
#     'TYPE_ENCODED_ARRAY_ITEM':0x2005,
#     'TYPE_ANNOTATIONS_DIRECTORY_ITEM':0x2006
# }

TYPE_CODES = {
    0x0000: 'TYPE_HEADER_ITEM',
    0x0001: 'TYPE_STRING_ID_ITEM',
    0x0002: 'TYPE_TYPE_ID_ITEM',
    0x0003: 'TYPE_PROTO_ID_ITEM',
    0x0004: 'TYPE_FIELD_ID_ITEM',
    0x0005: 'TYPE_METHOD_ID_ITEM',
    0x0006: 'TYPE_CLASS_DEF_ITEM',

    0x1000: 'TYPE_MAP_LIST',
    0x1001: 'TYPE_TYPE_LIST',
    0x1002: 'TYPE_ANNOTATION_SET_REF_LIST',
    0x1003: 'TYPE_ANNOTATION_SET_ITEM',

    0x2000: 'TYPE_CLASS_DATA_ITEM',
    0x2001: 'TYPE_CODE_ITEM',
    0x2002: 'TYPE_STRING_DATA_ITEM',
    0x2003: 'TYPE_DEBUG_INFO_ITEM',
    0x2004: 'TYPE_ANNOTATION_ITEM',
    0x2005: 'TYPE_ENCODED_ARRAY_ITEM',
    0x2006: 'TYPE_ANNOTATIONS_DIRECTORY_ITEM',
}


def uleb128_value(data, off):
    '''
        ULEB128 编码的整数值的读取方法
    :param data:
    :param off:
    :return:
    '''
    size = 1
    result = data[off + 0]
    if result > 0x7f:
        cur = data[off + 1]
        result = (result & 0x7f) | ((cur & 0x7f) << 7)
        size += 1
        if cur > 0x7f:
            cur = data[off + 2]
            result |= ((cur & 0x7f) << 14)
            size += 1
            if cur > 0x7f:
                cur = data[off + 3]
                result |= ((cur & 0x7f) << 21)
                size += 1
                if cur > 0x7f:
                    cur = data[off + 4]
                    result |= (cur << 28)
                    size += 1

    return result, size


def encoded_field(data, offset):
    myoff = offset

    field_idx_diff, size = uleb128_value(data, myoff)
    myoff += size
    access_flags, size = uleb128_value(data, myoff)
    myoff += size

    size = myoff - offset

    return [field_idx_diff, access_flags, size]


def encoded_method(data, offset):
    myoff = offset

    method_idx_diff, size = uleb128_value(data, myoff)
    myoff += size
    access_flags, size = uleb128_value(data, myoff)
    myoff += size
    code_off, size = uleb128_value(data, myoff)
    myoff += size

    size = myoff - offset

    return [method_idx_diff, access_flags, code_off, size]


def encoded_annotation(data, offset):
    myoff = offset

    type_idx_diff, size = uleb128_value(data, myoff)
    myoff += size
    size_diff, size = uleb128_value(data, myoff)
    myoff += size
    name_idx_diff, size = uleb128_value(data, myoff)
    myoff += size
    value_type = data[myoff:myoff + 1]
    encoded_value = data[myoff + 1:myoff + 2]

    return [type_idx_diff, size_diff, name_idx_diff, value_type, encoded_value]


def type2full(type_str, hash_list=False) -> str:
    if hash_list:
        add_list = "[]"
    else:
        add_list = ""
    if '[' in type_str:
        type_str = type_str.replace('[', "")
        return type2full(type_str, True)
    elif 'L' in type_str:
        type_str = type_str.replace('L', "")
        type_str = type_str.replace('/', '.')
        type_str = type_str.replace(';', "")
        return type_str + add_list
    else:
        return SHORT_TYPES[type_str] + add_list


def map_type(num: int)->str:
    try:
        return TYPE_CODES[num].lower()
    except KeyError:
        LOG.log_error(msg=f"TYPE {num} NOT FOUND")
        return "error"
    except Exception as e:
        LOG.log_error(msg=f"UNEXPECTED ERROR: {e}")
        return "error"
