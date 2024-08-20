import time
from io import BytesIO
from ctypes import c_byte, c_uint32, c_uint16

from typing import TypeVar
from zipfile import ZipFile, is_zipfile
import struct
import mmap
import os

from packages.dexparser import disassembler
from packages.dexparser.errors import InsufficientParameterError, IsNotAPKFileFormatError
from packages.dexparser.utils import uleb128_value, encoded_field, encoded_method, encoded_annotation, type2full, \
    map_type
from packages.log import LOG

from PyQt5.QtCore import pyqtSignal, QObject

from packages.mm_type import FileString, sizeof, read_file_from_struct
from packages.mm_type.mm_ctype import DataToCClass
from packages.mm_type.mm_dextype import Dex_HeaderItem, Dex_StringId_Item, structure, Dex_TypeId_Item, Dex_ProtoId_Item, \
    Dex_FieldId_Item, Dex_MethodId_Item, Dex_ClassDef_Item, Dex_Map_Item, Dex_class_data_item, Dex_class_data_field, \
    Dex_class_data_method, Dex_CodeItem, Dex_AnnotationsDirectory_Item, Dex_MethodAnnotation, Dex_ParameterAnnotation, \
    Dex_FieldAnnotation


# SHORT_TYPES={
#     'V': "void",
#     'Z': "boolean",
#     'B': "byte",
#     'S': "short",
#     'C': "char",
#     'I': "int",
#     'J': "long",
#     'F': "float",
#     'D': "double",
# }
class Dexparser(QObject):  # 因为要发信号,所以得继承Qobject

    sig_cost: pyqtSignal = pyqtSignal(float)

    def __init__(self, filedir=None):
        super().__init__()
        if filedir:
            if not os.path.isfile(filedir):
                raise FileNotFoundError
            self.file = open(filedir, 'rb')
            self.data = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)

        #确定端序
        end_tag = struct.unpack('<L', self.data[0x28:0x2C])[0]
        DataToCClass.order = (
            "little" if end_tag == 0x12345678 else "big"
        )

        # 声明一下把
        self.dex_header: Dex_HeaderItem = None
        self.dex_string_ids = []
        self.dex_type_ids = []
        self.dex_proto_ids = []
        self.dex_field_ids = []
        self.dex_method_ids = []
        self.dex_classdef_ids = []
        self.dex_map_list = []

        # 读取头部
        self.dex_init_header()
        # 读取并解析string_ids
        self.dex_init_string_ids()
        # 读取并解析type_ids
        self.dex_init_type_ids()
        # 读取并解析proto_ids
        self.dex_init_proto_ids()
        # 读取并解析field_ids
        self.dex_init_field_ids()
        # 读取并解析method_ids
        self.dex_init_method_ids()
        # 读取并解析classdef_ids
        self.dex_init_classdef_ids()
        # # 读取并解析map_list
        # self.dex_init_maplist()

        #回到最初的位置
        #self.file.seek(0)

    def dex_init_header(self):
        if self.dex_header is not None:
            return self.dex_header
        org_pos = self.file.tell()
        # -------------------------
        self.file.seek(0)
        self.dex_header: Dex_HeaderItem = read_file_from_struct(self.file, Dex_HeaderItem)
        #-------------------------
        self.file.seek(org_pos)
        return self.dex_header

    def dex_init_string_ids(self):
        if len(self.dex_string_ids) != 0:
            return self.dex_string_ids
        org_pos = self.file.tell()
        # -------------------------
        self.file.seek(self.dex_header.string_ids_off.value)
        for i in range(self.dex_header.string_ids_size.value):
            stringId_item_tmp = read_file_from_struct(self.file, Dex_StringId_Item)  #返回的是一个对象
            stringId_item_tmp.string_data_off.info = self.__parse_string_ids(stringId_item_tmp.string_data_off.value)
            self.dex_string_ids.append(stringId_item_tmp)
            # -------------------------
            self.sig_cost.emit(i / self.dex_header.string_ids_size.value)
        # -------------------------
        self.file.seek(org_pos)
        return self.dex_string_ids

    def dex_init_type_ids(self):
        if len(self.dex_type_ids) != 0:
            return self.dex_type_ids
        org_pos = self.file.tell()
        # -------------------------

        self.file.seek(self.dex_header.type_ids_off.value)
        for i in range(self.dex_header.type_ids_size.value):
            typeid_item_tmp = read_file_from_struct(self.file, Dex_TypeId_Item)
            tmp_str = self.dex_get_str(typeid_item_tmp.descriptor_idx.value)
            typeid_item_tmp.descriptor_idx.info = {
                'type_str': tmp_str,
                'full_type_str': type2full(tmp_str)
            }
            self.dex_type_ids.append(typeid_item_tmp)
            # -------------------------
            self.sig_cost.emit(i / self.dex_header.type_ids_size.value)

        # -------------------------
        self.file.seek(org_pos)
        return self.dex_type_ids

    def dex_init_proto_ids(self):
        if len(self.dex_proto_ids) != 0:
            return self.dex_proto_ids
        org_pos = self.file.tell()
        # -------------------------
        self.file.seek(self.dex_header.proto_ids_off.value)
        for i in range(self.dex_header.proto_ids_size.value):
            protoid_item_tmp = read_file_from_struct(self.file, Dex_ProtoId_Item)
            protoid_item_tmp.shorty_idx.info = self.dex_get_str(protoid_item_tmp.shorty_idx.value)
            protoid_item_tmp.return_type_idx.info = self.dex_get_type(protoid_item_tmp.return_type_idx.value)
            protoid_item_tmp.parameters_off.info = self.__parse_type_list_parameters_off(protoid_item_tmp.parameters_off.value)#没有返回空
            protoid_item_tmp.info = self.__parse_type_ids(protoid_item_tmp)
            self.dex_proto_ids.append(protoid_item_tmp)
            # -------------------------
            self.sig_cost.emit(i / self.dex_header.proto_ids_size.value)
        # -------------------------
        self.file.seek(org_pos)
        return self.dex_proto_ids

    def dex_init_field_ids(self):
        if len(self.dex_field_ids) != 0:
            return self.dex_field_ids
        org_pos = self.file.tell()
        # -------------------------

        self.file.seek(self.dex_header.field_ids_off.value)
        for i in range(self.dex_header.field_ids_size.value):
            field_id_item_tmp = read_file_from_struct(self.file, Dex_FieldId_Item)
            field_id_item_tmp.class_idx.info = self.dex_get_type(field_id_item_tmp.class_idx.value)
            field_id_item_tmp.type_idx.info = self.dex_get_type(field_id_item_tmp.type_idx.value)
            field_id_item_tmp.name_idx.info = self.dex_get_str(field_id_item_tmp.name_idx.value)
            field_id_item_tmp.info = self.__parse_field_ids(field_id_item_tmp)
            self.dex_field_ids.append(field_id_item_tmp)
            # -------------------------
            self.sig_cost.emit(i / self.dex_header.field_ids_size.value)
        # -------------------------
        self.file.seek(org_pos)
        return self.dex_field_ids

    def dex_init_method_ids(self):
        if len(self.dex_method_ids) != 0:
            return self.dex_method_ids
        org_pos = self.file.tell()
        # -------------------------

        self.file.seek(self.dex_header.method_ids_off.value)
        for i in range(self.dex_header.method_ids_size.value):
            method_id_item_tmp: Dex_MethodId_Item = read_file_from_struct(self.file, Dex_MethodId_Item)
            method_id_item_tmp.class_idx.info = self.dex_get_type(method_id_item_tmp.class_idx.value)
            method_id_item_tmp.proto_idx.info = self.dex_get_proto(method_id_item_tmp.proto_idx.value)
            method_id_item_tmp.name_idx.info = self.dex_get_str(method_id_item_tmp.name_idx.value)
            method_id_item_tmp.info = self.__parse_method_ids(method_id_item_tmp)
            self.dex_method_ids.append(method_id_item_tmp)
            # -------------------------
            self.sig_cost.emit(i / self.dex_header.method_ids_size.value)
        # -------------------------
        self.file.seek(org_pos)
        return self.dex_method_ids

    def dex_init_classdef_ids(self):
        if len(self.dex_classdef_ids) != 0:
            return self.dex_classdef_ids
        org_pos = self.file.tell()
        # -------------------------

        self.file.seek(self.dex_header.class_defs_off.value)
        for i in range(self.dex_header.class_defs_size.value):

            classdef_item_tmp: Dex_ClassDef_Item = read_file_from_struct(self.file, Dex_ClassDef_Item)

            classdef_item_tmp.class_idx.info = self.dex_get_type(classdef_item_tmp.class_idx.value)
            classdef_item_tmp.access_flags.info = self.__parse_access_flags("classes", classdef_item_tmp.access_flags.value)
            classdef_item_tmp.superclass_idx.info = self.dex_get_type( classdef_item_tmp.superclass_idx.value)  # 父类好像是一定存在的...那么是0
            classdef_item_tmp.interfaces_off.info = self.__parse_interfaces_off(classdef_item_tmp.interfaces_off.value)
            classdef_item_tmp.source_file_idx.info = self.dex_get_str(classdef_item_tmp.source_file_idx.value)
            #classdef_item_tmp.annotations_off.info = self.__parse_annotations_off(classdef_item_tmp.annotations_off.value)
            classdef_item_tmp.class_data_off.info = self.__parse_class_data(classdef_item_tmp.class_data_off.value)
            #classdef_item_tmp.static_values_off.info
            classdef_item_tmp.info = self.__parse_classdef_item(classdef_item_tmp)
            self.dex_classdef_ids.append(classdef_item_tmp)
        self.file.seek(org_pos)
        return self.dex_classdef_ids

    def dex_init_maplist(self):
        if len(self.dex_map_list) != 0:
            return self.dex_map_list
        org_pos = self.file.tell()
        # -------------------------
        offset = self.dex_header.map_off.value
        mapitem_cnt = struct.unpack('<L', self.data[offset:offset + 4])[0]

        self.file.seek(self.dex_header.map_off.value + 4)
        for i in range(mapitem_cnt):
            MapList_item_tmp = read_file_from_struct(self.file, Dex_Map_Item)
            MapList_item_tmp.info = map_type(MapList_item_tmp.type.value)
            self.dex_map_list.append(MapList_item_tmp)
            # -------------------------
            self.sig_cost.emit(i / mapitem_cnt)
        # -------------------------
        self.file.seek(org_pos)
        return self.dex_map_list

    # 最基础的3个get
    # dex_get_str, dex_get_type , dex_get_proto
    def dex_get_str(self, index: int) -> str:
        string_ids_len = len(self.dex_string_ids)
        if string_ids_len == 0:
            self.dex_init_string_ids()
            string_ids_len = len(self.dex_string_ids)
        if index == 0xffffffff:
            LOG.log_info(tag="dex_get_str",msg="NO INDEX")  #这个确实存在
            return self.dex_string_ids[0].string_data_off.info.str_cbytes.str
        if index >= string_ids_len:  #这个是异常
            LOG.log_error(tag="dex_get_str",msg="INDEX OUT OF RANGE")
            return " "
        return self.dex_string_ids[index].string_data_off.info.str_cbytes.str

    def dex_get_type(self, idx: int) -> str:
        '''
        默认返回类型全名称:
        :param idx:
        :return
        '''
        type_ids_len = len(self.dex_type_ids)
        if type_ids_len == 0:
            self.dex_init_type_ids()
            type_ids_len = len(self.dex_type_ids)
        if idx == 0xffffffff:
            LOG.log_error(tag="dex_get_type", msg="NO INDEX")
            return ""
        if idx >= type_ids_len:  # 这个是异常
            LOG.log_error(tag="dex_get_type", msg="INDEX OUT OF RANGE")
            return ""
        return self.dex_type_ids[idx].descriptor_idx.info['full_type_str']

    def dex_get_proto(self, idx: int) -> str:
        proto_ids_len = len(self.dex_proto_ids)
        if proto_ids_len == 0:
            self.dex_init_proto_ids()
            proto_ids_len = len(self.dex_proto_ids)
        if idx == 0xffffffff:
            LOG.log_error(tag="dex_get_proto", msg="NO INDEX")
            return " "
        if idx >= proto_ids_len:  # 这个是异常
            LOG.log_error(tag="dex_get_proto", msg="INDEX OUT OF RANGE")
            return " "
        return self.dex_proto_ids[idx].info

    def dex_get_field(self, index):
        field_ids_len = len(self.dex_field_ids)
        if field_ids_len == 0:
            self.dex_init_field_ids()
            field_ids_len = len(self.dex_field_ids)
        if index == 0xffffffff:
            LOG.log_error(tag="field", msg="NO INDEX")
            return " "
        if index >= field_ids_len:  # 这个是异常
            LOG.log_error(tag="field", msg="INDEX OUT OF RANGE")
            return " "
        return self.dex_field_ids[index].info

    def dex_get_method(self, index):
        method_ids_len = len(self.dex_method_ids)
        if method_ids_len == 0:
            self.dex_init_method_ids()
            method_ids_len = len(self.dex_method_ids)
        if index == 0xffffffff:
            LOG.log_error(tag="method", msg="NO INDEX")
            return " "
        if index >= method_ids_len:  # 这个是异常
            LOG.log_error(tag="method", msg="INDEX OUT OF RANGE")
            return " "
        return self.dex_method_ids[index].info

    def __parse_string_ids(self, offset):  #属于临时的解析,所以fseek后,要把指针指回去
        org_fpostion = self.file.tell()
        # -------------------------
        self.file.seek(offset)

        str_len, str_len_size = uleb128_value(self.data, offset)

        @structure
        class new_string_item:
            len_size: c_byte * str_len_size
            str_cbytes: c_byte * str_len

        string_item_tmp = read_file_from_struct(self.file, new_string_item)
        string_item_tmp.str_cbytes.str = string_item_tmp.str_cbytes._data_.decode('utf-8', errors='ignore')
        # -------------------------
        self.file.seek(org_fpostion)
        return string_item_tmp

    def __parse_type_ids(self, proto_item) -> str:
        if proto_item.parameters_off.info == None:
            parameters_str = "()"
        else:
            parameters_str = proto_item.parameters_off.info.info
        return proto_item.return_type_idx.info + " " + parameters_str

    def __parse_field_ids(self, field_id_item) -> str:
        return field_id_item.type_idx.info + " " + \
            field_id_item.class_idx.info + "." + \
            field_id_item.name_idx.info

    def __parse_method_ids(self, method_id_item) -> str:
        proto_full_name = method_id_item.proto_idx.info
        # class_type_str=self.__type_ids[class_idx]['type_str']
        # if 'L' not in class_type_str or ';' not in class_type_str: #在有限的认知下, 该类型一定是一个 class 类, 后来发现类不一定是L开头, ';'结尾
        #     raise Exception('proto_str error')
        met_proto_split = proto_full_name.index(" ")  # str.find()找不到返回-1, index会抛出异常
        ret_type_str = proto_full_name[:met_proto_split]
        arg_type_str = proto_full_name[met_proto_split + 1:]  # 不从空格开始
        full_method_str = ret_type_str + " " + method_id_item.class_idx.info + "." + method_id_item.name_idx.info + arg_type_str
        return full_method_str

    def __parse_access_flags(self, type_str, access_flags) -> str:
        sorted_access = [i for i in disassembler.ACCESS_ORDER if i & access_flags]  # 把属性拆开
        access_str = ""
        flag_len = len(sorted_access)
        if len(sorted_access) != 0:
            if type_str == 'methods':
                access_flag = disassembler.access_flag_methods
            elif type_str == 'fields':
                access_flag = disassembler.access_flag_fields
            elif type_str == 'classes':
                access_flag = disassembler.access_flag_classes
            else:
                raise Exception('[__parse_access_flags] => type_str error')
            for i in range(flag_len):
                flag = sorted_access[i]
                access_str = access_str + access_flag[flag]
                if i + 1 < flag_len:
                    access_str = access_str + " "
        return access_str

    def __parse_interfaces_off(self, offset) -> str:
        org_pos = self.file.tell()
        # -------------------------
        interfaces_str = ""
        if offset != 0:
            interfaces_cnt = struct.unpack('<L', self.data[offset:offset + 4])[0]

            @structure
            class new_interfaces_typelist:
                size_: c_uint32
                list_: c_uint16 * interfaces_cnt

            self.file.seek(offset)
            interfaces_typelist_item = read_file_from_struct(self.file, new_interfaces_typelist)

            for i in range(interfaces_cnt):
                interfaces_str = interfaces_str + self.dex_get_type(interfaces_typelist_item.list_[i])
                if i + 1 < interfaces_cnt:
                    interfaces_str = interfaces_str + ","

        # -------------------------
        self.file.seek(org_pos)
        return interfaces_str

    def __parse_classdef_item(self, classdef_item_tmp) -> str:
        out_str = ''
        if len(classdef_item_tmp.access_flags.info) != 0:
            out_str = out_str + classdef_item_tmp.access_flags.info + ' '
        if len(classdef_item_tmp.class_idx.info) != 0:
            out_str = out_str + classdef_item_tmp.class_idx.info + ' '
        if len(classdef_item_tmp.superclass_idx.info) != 0:
            out_str = out_str + "extends " + classdef_item_tmp.superclass_idx.info + ' '
        if len(classdef_item_tmp.interfaces_off.info) != 0:
            out_str = out_str + "implements " + classdef_item_tmp.interfaces_off.info + ' '
        if len(classdef_item_tmp.source_file_idx.info) != 0:
            out_str = out_str + "from " + classdef_item_tmp.source_file_idx.info
        return out_str

    def __parse_type_list_parameters_off(self, offset):
        org_pos = self.file.tell()
        # -------------------------
        if offset == 0:
            return None
        arg_cnt = struct.unpack('<L', self.data[offset: offset + 4])[0]
        if arg_cnt == 0:
            raise ValueError('[__parse_type_list_parameters_off] => arg_cnt == 0')

        self.file.seek(offset)

        @structure
        class new_TypeList:
            size_: c_uint32
            list_: c_uint16 * arg_cnt  #不知道为什么是 list[int]类型,而不是list[uint16]

        info = "("
        TypeListItem = read_file_from_struct(self.file, new_TypeList)
        for i in range(arg_cnt):
            info = info + self.dex_get_type(TypeListItem.list_[i])
            if i + 1 < arg_cnt:
                info = info + ","
        info = info + ")"
        new_TypeList.info = info
        # -------------------------
        self.file.seek(org_pos)
        return TypeListItem


    def __parse_annotations_off(self, offset):
        if offset == 0:
            return None
        org_pos = self.file.tell()
        self.file.seek(offset)
        AnnotationsDirectory_Item_tmp = read_file_from_struct(self.file, Dex_AnnotationsDirectory_Item)

        AnnotationsDirectory_Item_tmp.class_annotations_off.info = self.__parse_class_annotations_off(
            AnnotationsDirectory_Item_tmp.class_annotations_off.value)

        AnnotationsDirectory_Item_tmp.field_annotations = []
        for i in range(AnnotationsDirectory_Item_tmp.annotated_fields_size.value):
            FieldAnnotation_item = read_file_from_struct(self.file, Dex_FieldAnnotation)
            AnnotationsDirectory_Item_tmp.field_annotations.append(
                FieldAnnotation_item
            )

        AnnotationsDirectory_Item_tmp.method_annotations = []
        for i in range(AnnotationsDirectory_Item_tmp.annotated_methods_size.value):
            MethodAnnotation_item = read_file_from_struct(self.file, Dex_MethodAnnotation)
            AnnotationsDirectory_Item_tmp.method_annotations.append(
                MethodAnnotation_item
            )

        AnnotationsDirectory_Item_tmp.parameter_annotations = []
        for i in range(AnnotationsDirectory_Item_tmp.annotated_parameters_size.value):
            ParameterAnnotation_item = read_file_from_struct(self.file, Dex_ParameterAnnotation)
            AnnotationsDirectory_Item_tmp.method_annotations.append(
                ParameterAnnotation_item
            )
        self.file.seek(org_pos)
        return AnnotationsDirectory_Item_tmp

    def __parse_class_data_fields(self,field_size,offset):
        org_pos = self.file.tell()
        ret_list = []
        for i in range(field_size):
            field_idx_diff, access_flags, size1, size2 = encoded_field(self.data, offset)
            if i == 0:
                diff = field_idx_diff
            else:
                diff += field_idx_diff

            @structure
            class new_class_data_field_item:
                field_idx: c_byte * size1
                access_flags: c_byte * size2

            self.file.seek(offset)
            class_data_field_item_tmp = read_file_from_struct(self.file, new_class_data_field_item)
            class_data_field_item_tmp.field_idx.info = diff
            class_data_field_item_tmp.access_flags.info = access_flags
            class_data_field_item_tmp.info = self.__parse_access_flags("fields",class_data_field_item_tmp.access_flags.info) + " " + self.dex_get_field(class_data_field_item_tmp.field_idx.info)

            ret_list.append(class_data_field_item_tmp)
            offset += (size1 + size2)

        self.file.seek(org_pos)
        return ret_list,offset

    def __parse_class_data_methods(self,method_size,offset):
        org_pos = self.file.tell()
        ret_list = []
        for i in range(method_size):
            method_idx_diff, access_flags, code_off, size1,size2,size3 = encoded_method(self.data, offset)
            if i == 0:
                diff = method_idx_diff
            else:
                diff += method_idx_diff

            @structure
            class new_class_data_method_item:
                method_idx: c_byte * size1
                access_flags: c_byte * size2
                code_off: c_byte * size3

            self.file.seek(offset)
            class_data_method_item_tmp = read_file_from_struct(self.file, new_class_data_method_item)
            class_data_method_item_tmp.method_idx.info = diff
            class_data_method_item_tmp.access_flags.info = access_flags
            class_data_method_item_tmp.code_off.info = {
                'value': code_off,
                'info': None
            }
            class_data_method_item_tmp.code_off.info['info'] = self.__parse_code_item(class_data_method_item_tmp.code_off.info['value'])
            class_data_method_item_tmp.info = self.__parse_access_flags("methods", class_data_method_item_tmp.access_flags.info) +  " " +  self.dex_get_method(class_data_method_item_tmp.method_idx.info)
            ret_list.append(class_data_method_item_tmp)
            offset += (size1 + size2 + size3)
        self.file.seek(org_pos)
        return ret_list,offset

    def __parse_class_data(self, offset):
        if offset == 0:
            return None

        org_pos = self.file.tell()
        # -------------------------

        self.file.seek(offset)
        static_field_size, sf_size = uleb128_value(self.data, offset)
        offset += sf_size

        instance_field_size, if_size = uleb128_value(self.data, offset)
        offset += if_size

        direct_method_size, dm_size = uleb128_value(self.data, offset)
        offset += dm_size

        virtual_method_size, vm_size = uleb128_value(self.data, offset)
        offset += vm_size

        @structure
        class new_class_data_item:
            static_fields_size : c_byte * sf_size
            instance_fields_size : c_byte * if_size
            direct_methods_size : c_byte * dm_size
            virtual_methods_size : c_byte * vm_size

        #self.file.seek(offset)
        class_data_item_tmp = read_file_from_struct(self.file, new_class_data_item)
        class_data_item_tmp.static_fields_size.info = static_field_size
        class_data_item_tmp.instance_fields_size.info = instance_field_size
        class_data_item_tmp.direct_methods_size.info = direct_method_size
        class_data_item_tmp.virtual_methods_size.info = virtual_method_size
        #动态性创建成员
        if static_field_size !=0:
            class_data_item_tmp.static_fields , offset = self.__parse_class_data_fields(static_field_size,offset)
        if instance_field_size !=0:
            class_data_item_tmp.instance_fields , offset = self.__parse_class_data_fields(instance_field_size,offset)
        if direct_method_size !=0:
            class_data_item_tmp.direct_methods ,offset = self.__parse_class_data_methods(direct_method_size,offset)
        if virtual_method_size !=0:
            class_data_item_tmp.virtual_methods  ,offset = self.__parse_class_data_methods(virtual_method_size,offset)

        # -------------------------
        self.file.seek((org_pos))
        return class_data_item_tmp

    def __parse_code_item(self, offset):
        org_pos = self.file.tell()
        self.file.seek(offset)
        code_item_tmp = read_file_from_struct(self.file, Dex_CodeItem)
        code_item_tmp.insns = self.file.read(code_item_tmp.insns_size.value)
        self.file.seek((org_pos))
        return code_item_tmp

    def __parse_class_annotations_off(self, offset):
        org_pos = self.file.tell()
        self.file.seek(offset)
        annotation_size = struct.unpack('<L', self.data[offset: offset + 4])[0]
        if annotation_size == 0:
            raise ValueError('annotation_size == 0')

        @structure
        class new_class_annotations_item:
            size: c_uint32
            entries: c_uint32 * annotation_size

        class_annotations_item_tmp = read_file_from_struct(self.file, new_class_annotations_item)
        #AnnotationsDirectory_Item_tmp = read_file_from_struct(self.file, Dex_AnnotationsDirectory_Item)

        self.file.seek((org_pos))
        return

    def get_annotations(self, offset):
        """Get annotation data from DEX file

        :param integer offset: annotation_off offset value
        :returns: specific data of annotation

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.get_annotations(offset=3022)
            {
                'visibility': 3403,
                'type_idx_diff': 3024,
                'size_diff': 64,
                'name_idx_diff': 30,
                'value_type': 302,
                'encoded_value': 7483
            }
        """
        class_annotation_off = struct.unpack('<L', self.data[offset:offset + 4])[0]
        class_annotation_size = struct.unpack('<L', self.data[class_annotation_off:class_annotation_off + 4])[0]
        annotation_off_item = struct.unpack('<L', self.data[class_annotation_off + 4: class_annotation_off + 8])[0]
        visibility = self.data[annotation_off_item: annotation_off_item + 1]
        annotation = self.data[annotation_off_item + 1: annotation_off_item + 8]
        annotation_data = encoded_annotation(self.data, annotation_off_item + 1)
        type_idx_diff, size_diff, name_idx_diff, value_type, encoded_value = annotation_data

        return {
            'visibility': ord(visibility),
            'type_idx_diff': type_idx_diff,
            'size_diff': size_diff,
            'name_idx_diff': name_idx_diff,
            'value_type': ord(value_type),
            'encoded_value': ord(encoded_value)
        }

    def get_static_values(self, offset):
        """Get all static values parsed from 'static_values_off' classdef_data section.

        :param integer offset: static_values_off offset value
        :returns: specific data of static values

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.get_static_values(offset=3022)
            [b'android.annotation', 0.0, False, None]
        """
        size, size_off = uleb128_value(self.data, offset)
        offset += size_off
        result = []

        _strings = self.init_string_ids()

        for _ in range(size):
            value_arg = self.data[offset] >> 5
            value_type = self.data[offset] & 0b11111
            offset += 1

            if value_type == 0x00 or \
                    value_type == 0x02 or \
                    value_type == 0x03 or \
                    value_type == 0x04 or \
                    value_type == 0x06 or \
                    value_type == 0x18 or \
                    value_type == 0x19 or \
                    value_type == 0x1a or \
                    value_type == 0x1b:
                # VALUE_BYTE, VALUE_SHORT, VALUE_CHAR, VALUE_INT, VALUE_LONG, VALUE_TYPE
                # VALUE_TYPE, VALUE_FIELD, VALUE_METHOD, VALUE_ENUM
                value = 0
                for i in range(value_arg + 1):
                    value |= (self.data[offset] << 8 * i)
                    offset += 1
                result.append(value)

            elif value_type == 0x10 or value_type == 0x11:  # VALUE_FLOAT, VALUE_DOUBLE
                value = 0
                for i in range(value_arg + 1):
                    value |= (self.data[offset] << 8 * i)
                    offset += 1
                result.append(float(value))

            elif value_type == 0x17:  # VALUE_STRING
                string_off = 0
                for i in range(value_arg + 1):
                    string_off |= (self.data[offset] << 8 * i)
                    offset += 1
                result.append(_strings[string_off])

            elif value_type == 0x1c:  # VALUE_ARRAY
                result.append(self.get_static_values(offset))

            elif value_type == 0x1d:  # VALUE_ANNOTATION
                result.append(
                    encoded_annotation(self.data, offset)
                )

            elif value_type == 0x1f:  # VALUE_BOOLEAN
                result.append(bool(value_arg))

            else:  # VALUE_NULL
                result.append(None)

        return result

# apk fiels
# class APKParser(object):
#     """APK file format parser class
#     :param string filedir: APK file path
#     :param bytes fileobj: APK file object
#     :param boolean deepscan: Scan all assets of APK file for detect adex file
#     """
#
#     def __init__(self, filedir=None, fileobj=None, deepscan=False):
#         if not filedir and not fileobj:
#             raise InsufficientParameterError('fileobj or filedir parameter required.')
#
#         if filedir:
#             if not os.path.isfile(filedir):  #检查给定的路径是否指向一个普通的文件
#                 raise FileNotFoundError
#
#             if not is_zipfile(filedir):  #检查给定的路径是否指向一个zip文件
#                 raise IsNotAPKFileFormatError("{} is not an APK file format.".format(filedir))
#
#             self.zfile = ZipFile(filedir)  #打开zip文件
#
#         if fileobj:
#             if not is_zipfile(BytesIO(fileobj)):
#                 raise IsNotAPKFileFormatError("Invalid APK file format.")
#
#             self.zfile = ZipFile(BytesIO(fileobj))
#
#         self.dexfiles = {}  #字典
#
#         if deepscan:
#             for filename in self.zfile.namelist():
#                 stream = self.zfile.read(filename)
#                 if len(stream) < 8:
#                     continue
#
#                 if stream[0:4] == "dex\x0a":
#                     self.dexfiles[filename] = DEXParser(fileobj=stream)
#
#         else:
#             for filename in self.zfile.namelist():
#                 if filename.endswith(".dex"):
#                     self.dexfiles[filename] = DEXParser(fileobj=self.zfile.read(filename))
#
#     @property
#     def is_multidex(self):
#         """Detect if APK is a multidex
#         https://developer.android.com/studio/build/multidex
#
#         :returns: boolean
#
#         example:
#             >>> APKParser(filedir='path/to/file.apk').is_multidex
#             True
#         """
#         return len(self.dexfiles.keys()) > 1
#
#     def get_dex(self, filename="classes.dex"):
#         """Get dex file with DEX parsed object
#
#         :params: name of dexfile (default: classes.dex)
#         :returns: DEXParser object
#
#         example:
#             >>> APKParser(filedir='path/to/file.apk').get_dex()
#             True
#         """
#         return self.dexfiles[filename]
#
#     def get_all_dex_filenames(self):
#         """Get all name of dex files
#         :returns: list of dex filenames
#
#         example:
#             >>> APKParser(filedir='path/to/file.apk').get_all_dex_filenames()
#             ['classes.dex', 'classes1.dex']
#         """
#         return list(self.dexfiles.keys())
#
#
# class AABParser(APKParser):
#     """AAB (Android App Bundle) file format parser class
#     :param string filedir: AAB file path
#     :param bytes fileobj: AAB file object
#     :param boolean deepscan: Scan all assets of AAB file for detect adex file
#     """
#     pass
#
#
# class DEXParser(Dexparser):
#     """DEX file format parser subclass
#     :param string filedir: DEX file path
#     :param bytes fileobj: DEX file object
#     """
#     pass
