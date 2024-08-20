
from ctypes import (
    c_byte,
    c_ubyte,
    c_uint16,
    c_int32,
    c_uint32,
    c_int64,
    c_uint64,
    c_char,
)

from packages.mm_type import BaseStructure


def structure(cls: type) -> type:
    """
    This decorator helps to build C Structures.
    """

    def wrap(cls: type) -> type:
        """
        This function builds the C Structure class.
        """

        return type(
            cls.__name__,
            (cls, BaseStructure),
            {"__annotations__": cls.__annotations__},
        )

    return wrap(cls)

@structure
class Dex_HeaderItem:
    magic: c_byte * 8
    checksum: c_uint32
    signature: c_byte * 20
    file_size: c_uint32
    header_size: c_uint32
    endian_tag: c_uint32
    link_size: c_uint32
    link_off: c_uint32
    map_off: c_uint32
    string_ids_size: c_uint32
    string_ids_off: c_uint32
    type_ids_size: c_uint32
    type_ids_off: c_uint32
    proto_ids_size: c_uint32
    proto_ids_off: c_uint32
    field_ids_size: c_uint32
    field_ids_off: c_uint32
    method_ids_size: c_uint32
    method_ids_off: c_uint32
    class_defs_size: c_uint32
    class_defs_off: c_uint32
    data_size: c_uint32
    data_off: c_uint32


@structure
class Dex_StringId_Item:
  string_data_off: c_uint32

@structure
class Dex_TypeId_Item :
  descriptor_idx: c_uint32

@structure
class Dex_ProtoId_Item:
  shorty_idx: c_uint32
  return_type_idx: c_uint32
  parameters_off: c_uint32

@structure
class Dex_FieldId_Item :
  class_idx: c_uint16
  type_idx: c_uint16
  name_idx: c_uint32

@structure
class Dex_MethodId_Item :
   class_idx: c_uint16
   proto_idx: c_uint16
   name_idx: c_uint32

@structure
class Dex_ClassDef_Item :
   class_idx:c_uint32
   access_flags:c_uint32
   superclass_idx:c_uint32
   interfaces_off:c_uint32
   source_file_idx:c_uint32
   annotations_off:c_uint32
   class_data_off:c_uint32
   static_values_off:c_uint32


# class MapList:
#   size: c_uint32
#   list

@structure
class Dex_Map_Item :
  type: c_uint16
  unused: c_uint16
  size: c_uint32
  offset: c_uint32


@structure
class Dex_CodeItem :
    registers_size: c_uint16
    ins_size: c_uint16
    outs_size: c_uint16
    tries_size: c_uint16
    debug_info_off: c_uint32
    insns_size: c_uint32
  #// Variable length data follow for complete code item.

@structure
class Dex_AnnotationsDirectory_Item :
  class_annotations_off:c_uint32
  fields_size:c_uint32
  annotated_methods_size:c_uint32
  annotated_parameters_size:c_uint32
  field_annotations = None
  method_annotations = None
  parameter_annotations = None


@structure
class Dex_FieldAnnotation :
  field_idx: c_uint32
  annotations_off: c_uint32
@structure
class Dex_MethodAnnotation :
   method_idx: c_uint32
   annotations_off: c_uint32


@structure
class Dex_ParameterAnnotation :
   method_idx: c_uint32
   annotations_off: c_uint32











