import time
from io import BytesIO
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
class Dexparser(QObject):
    """DEX file format parser class
    :param string filedir: DEX file path
    :param bytes fileobj: DEX file object
    """
    sig_cost: pyqtSignal = pyqtSignal(float)

    def __init__(self, filedir=None, fileobj=None):
        super().__init__()
        if not filedir and not fileobj:
            raise InsufficientParameterError('fileobj or filedir parameter required.')

        if filedir:
            if not os.path.isfile(filedir):
                raise FileNotFoundError

            with open(filedir, 'rb') as f:
                self.data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        if fileobj:
            self.data = fileobj



        self.header_data = { #字典, 直接从数据里面取
            'magic': self.data[0:8],
            'checksum': struct.unpack('<L', self.data[8:0xC])[0],
            'signiture': self.data[0xC:0x20],
            'file_size': struct.unpack('<L', self.data[0x20:0x24])[0],
            'header_size': struct.unpack('<L', self.data[0x24:0x28])[0],
            'endian_tag': struct.unpack('<L', self.data[0x28:0x2C])[0],
            'link_size': struct.unpack('<L', self.data[0x2C:0x30])[0],
            'link_off': struct.unpack('<L', self.data[0x30:0x34])[0],
            'map_off': struct.unpack('<L', self.data[0x34:0x38])[0],
            'string_ids_size': struct.unpack('<L', self.data[0x38:0x3C])[0],
            'string_ids_off': struct.unpack('<L', self.data[0x3C:0x40])[0],
            'type_ids_size': struct.unpack('<L', self.data[0x40:0x44])[0],
            'type_ids_off': struct.unpack('<L', self.data[0x44:0x48])[0],
            'proto_ids_size': struct.unpack('<L', self.data[0x48:0x4C])[0],
            'proto_ids_off': struct.unpack('<L', self.data[0x4C:0x50])[0],
            'field_ids_size': struct.unpack('<L', self.data[0x50:0x54])[0],
            'field_ids_off': struct.unpack('<L', self.data[0x54:0x58])[0],
            'method_ids_size': struct.unpack('<L', self.data[0x58:0x5C])[0],
            'method_ids_off': struct.unpack('<L', self.data[0x5C:0x60])[0],
            'class_defs_size': struct.unpack('<L', self.data[0x60:0x64])[0],
            'class_defs_off': struct.unpack('<L', self.data[0x64:0x68])[0],
            'data_size': struct.unpack('<L', self.data[0x68:0x6C])[0],
            'data_off': struct.unpack('<L', self.data[0x6C:0x70])[0]
        }
        self.Dex={
            'string_ids':{
                'content': None,
                'loaded': False
            },
            'type_ids': {
                'content': None,
                'loaded': False
            },
            'proto_ids': {
                'content': None,
                'loaded': False
            },
            'field_ids': {
                'content':None,
                'loaded': False
            },
            'method_ids': {
                'content': None,
                'loaded': False
            },
            'classdef_ids': {
                'content': None,
                'loaded': False
            },
            'maplists': {
                'content': None,
                'loaded': False
            }
        }
        #自定义添加
        '''
        str_mem = {
            'len_size': str_len_size,
            'len': str_len,
            'str': dex_string
        }
        type_mem={
            'type_idx'(int): 索引值 .
            'type_str'(str): 类型的名称
            'full_type_str (str)': 类型的全名称
        }
        proto_mem={
            'shorty_idx': shorty_idx,
            'return_type_idx': return_type_idx,
            'param_off': param_off,
            # 自定义添加
            'short_str': self.__string_ids[shorty_idx]['str'],
            'full_proto_str': full_proto_str
        }
        field_mem={
            'class_idx': class_idx,
            'type_idx': type_idx,
            'name_idx': name_idx,
            'full_field_str':full_field_str
        }

        field_mem={
            'class_idx': class_idx,
            'proto_idx': proto_idx,
            'name_idx': name_idx,
            # 自定义
            'full_method_str': full_method_str
        }
        cls_def_mem={
            'class_idx': class_idx,
            'access': access_flag,
            'superclass_idx': superclass_idx,
            'interfaces_off': interfaces_off,
            'source_file_idx': source_file_idx,
            'annotation_off': annotation_off,
            'class_data_off': class_data_off,
            'static_values_off': static_values_off,
            #自定义
            'full_class_name':full_class_name
        }
           map_item={
                'section_type': section_type,
                'section_size': section_size,
                'section_offset': section_offset,
                'section_type_str': map_type(section_type)
            }
        '''

    @property
    def header(self):
        """Get header data from DEX

        :returns: header data

        example:
            >>> Dexparser(filedir='path/to/classes.dex').header
            {'magic': 'dex\x035' ...}
        """
        return self.header_data

    @property
    def checksum(self):
        """Get checksum value of DEX file

        :returns: hexlify value of checksum

        example:
            >>> Dexparser(filedir='path/to/classes.dex').checksum
            0x30405060
        """
        return "%x" % self.header_data.get('checksum')

    def init_string_ids(self):
        if self.Dex['string_ids']['loaded']:
            return self.Dex['string_ids']['content']
        """Get string items from DEX file

        :returns: list, list member is [clen,csize,c_char]

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.get_strings()
            ['Ljava/Page/getJavaUtils', ...]
        """
        LOG.log_info(tag="dexparser", msg="init_string_ids")
        strings = []
        string_ids_off = self.header_data['string_ids_off']
        str_ids_len=self.header_data['string_ids_size']

        for i in range(str_ids_len):
            idx=string_ids_off + (i * 4)
            offset = struct.unpack('<L', self.data[idx : idx + 4])[0]
            str_len, str_len_size = uleb128_value(self.data, offset)
            '''
            struct string_def
            {
                byte str_length;//字符串长度，不含0
                byte str_data[1];//柔性数组，字符串内容，以0结尾
            }
            '''

            dex_string = self.data[offset + str_len_size:offset + str_len_size + str_len].decode('utf-8',errors='ignore')
            #出现一个问题, 如果对应的字符串不是utf-8编码,解码得到的不是字符串,那么之后的处理可能受到影响

            str_mem = {
                'len_size': str_len_size,
                'len': str_len,
                'str': dex_string
            }
            strings.append(str_mem)# 长度,数值,字节流
            self.sig_cost.emit(i / str_ids_len )# 进度展示

        self.Dex['string_ids']['content']=strings
        self.Dex['string_ids']['loaded']=True

        self.sig_cost.emit(1)  # 100%进度展示
        return strings
    def get_str(self,index:int)->str:
        if self.Dex['string_ids']['loaded']==False:
            self.init_string_ids()
        if index==0xffffffff:
            LOG.log_info(msg="NO INDEX") #这个确实存在
            return self.Dex['string_ids']['content'][0]['str']
        if index>=len(self.Dex['string_ids']['content']): #这个是异常
            LOG.log_error(msg="INDEX OUT OF RANGE")
            return " "
        return self.Dex['string_ids']['content'][index]['str']

    def init_type_ids(self):
        """Get type ids from DEX file

        :returns: descriptor_idx extracted from type_id_item section

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.init_type_ids()
            [133, 355, 773, 494, ...]
        """
        if self.Dex['type_ids']['loaded']:
            return self.Dex['type_ids']['content']

        #env
        # string_ids会自动加载
        LOG.log_info(tag="dexparser", msg="init_type_ids")

        typeids = []
        offset = self.header_data['type_ids_off']
        type_ids_len=self.header_data['type_ids_size']
        for i in range(type_ids_len):
            idx = struct.unpack('<L', self.data[offset + (i * 4):offset + (i * 4) + 4])[0]
            type_mem={
                'type_idx':idx,
                'type_str': self.get_str(idx),
                'full_type_str': type2full(self.get_str(idx))
            }
            typeids.append(type_mem)
            self.sig_cost.emit(i / type_ids_len)# 进度展示


        self.Dex['type_ids']['content']=typeids
        self.Dex['type_ids']['loaded']=True

        self.sig_cost.emit(1)  # 100%进度展示
        return typeids

    def get_type(self,idx:int):
        '''
        默认返回类型全名称:
        :param idx:
        :return
        '''
        if self.Dex['type_ids']['loaded']==False:
            self.init_type_ids()
        if idx==0xffffffff:
            LOG.log_error(tag="type",msg="NO INDEX")
            return " "
        if idx>=len(self.Dex['type_ids']['content']): #这个是异常
            LOG.log_error(tag="type",msg="INDEX OUT OF RANGE")
            return " "
        return self.Dex['type_ids']['content'][idx]['full_type_str']

    def init_proto_ids(self):
        """Get proto idx from DEX file

        :returns: list of proto ids defined at proto_id_item

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.init_proto_ids()
            [{'shorty_idx': 3000, 'return_type_idx': 330, 'param_off': 0}, ...]
        """

        if self.Dex['proto_ids']['loaded']:
            return self.Dex['proto_ids']['content']
        LOG.log_info(tag="dexparser", msg="init_proto_ids")
        protoids = []
        offset = self.header_data['proto_ids_off']
        ptoto_ids_len=self.header_data['proto_ids_size']
        for i in range(ptoto_ids_len):
            sizeof_ProtoId=12
            tmp_idx=i * sizeof_ProtoId
            shorty_idx = struct.unpack('<L', self.data[offset + tmp_idx:offset + tmp_idx + 4])[0]
            return_type_idx = struct.unpack('<L', self.data[offset + tmp_idx + 4:offset + tmp_idx + 8])[0]
            param_off = struct.unpack('<L', self.data[offset + tmp_idx + 8:offset + tmp_idx + 12])[0]
            #=== 自定义添加
            if param_off!=0:#有参数
                args_type_str = "( "
                arg_cnt=struct.unpack('<L', self.data[param_off:param_off + 4])[0]
                for i in range(arg_cnt):
                    arg_type_id=struct.unpack('<H', self.data[param_off + 4 + 2*i : param_off + 6+ 2*i])[0]
                    args_type_str = args_type_str + self.get_type(arg_type_id)
                    if i+1<arg_cnt:
                        args_type_str = args_type_str + ", "
                args_type_str = args_type_str + " )"
            else:
                args_type_str = "( )"
            full_proto_str=self.get_type(return_type_idx) + " " + args_type_str
            proto_mem={
                'shorty_idx': shorty_idx,
                'return_type_idx': return_type_idx,
                'param_off': param_off,
                # 自定义添加
                'short_str': self.get_str(shorty_idx),
                'full_proto_str': full_proto_str
            }
            protoids.append(proto_mem)
            self.sig_cost.emit(i / ptoto_ids_len)# 进度展示


        self.Dex['proto_ids']['content']=protoids
        self.Dex['proto_ids']['loaded']=True

        self.sig_cost.emit(1)  # 100%进度展示
        return protoids

    def get_proto(self, idx:int):

        if self.Dex['proto_ids']['loaded']==False:
            self.init_proto_ids()
        if idx==0xffffffff:
            LOG.log_error(tag="proto",msg="NO INDEX")
            return " "
        if idx>=len(self.Dex['proto_ids']['content']): #这个是异常
            LOG.log_error(tag="proto",msg="INDEX OUT OF RANGE")
            return " "
        return self.Dex['proto_ids']['content'][idx]['full_proto_str']


    def init_field_ids(self):
        """Get field idx from DEX file

        :returns: list of field ids defined at field_id_item

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.init_field_ids()
            [{'class_idx': 339, 'type_idx': 334, 'name_idx': 340}, ...]
        """
        if self.Dex['field_ids']['loaded']:
            return self.Dex['field_ids']['content']
        LOG.log_info(tag="dexparser", msg="init_field_ids")
        fieldids = []
        offset = self.header_data['field_ids_off']
        field_ids_len=self.header_data['field_ids_size']
        for i in range(field_ids_len):
            class_idx = struct.unpack('<H', self.data[offset + (i * 8):offset + (i * 8) + 2])[0]
            type_idx = struct.unpack('<H', self.data[offset + (i * 8) + 2:offset + (i * 8) + 4])[0]
            name_idx = struct.unpack('<L', self.data[offset + (i * 8) + 4:offset + (i * 8) + 8])[0]
            full_field_str=self.get_type(type_idx) + " " + self.get_type(class_idx) + "." + self.get_str(name_idx)
            field_mem={
                'class_idx': class_idx,
                'type_idx': type_idx,
                'name_idx': name_idx,
                'full_field_str':full_field_str
            }
            fieldids.append(field_mem)
            self.sig_cost.emit(i / field_ids_len)#进度展示

        self.Dex['field_ids']['content']=fieldids
        self.Dex['field_ids']['loaded']=True

        self.sig_cost.emit(1)  # 100%进度展示
        return fieldids

    def get_field(self,idx:int):
        if self.Dex['field_ids']['loaded']==False:
            self.init_field_ids()
        if idx==0xffffffff:
            LOG.log_error(tag="field",msg="NO INDEX")
            return " "
        if idx>=len(self.Dex['field_ids']['content']): #这个是异常
            LOG.log_error(tag="field",msg="INDEX OUT OF RANGE")
            return " "
        return self.Dex['field_ids']['content'][idx]['full_field_str']
    def init_method_ids(self):
        """Get methods from DEX file

        :returns: list of methods defined at DEX file

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.init_method_ids()
            [{'class_idx': 132, 'proto_idx': 253, 'name_idx': 3005}, ...]
        """
        if self.Dex['method_ids']['loaded']:
            return self.Dex['method_ids']['content']

        LOG.log_info(tag="dexparser", msg="init_method_ids")
        methods = []
        offset = self.header_data['method_ids_off']
        method_ids_len=self.header_data['method_ids_size']
        for i in range(method_ids_len):
            class_idx = struct.unpack('<H', self.data[offset + (i * 8):offset + (i * 8) + 2])[0]
            proto_idx = struct.unpack('<H', self.data[offset + (i * 8) + 2:offset + (i * 8) + 4])[0]
            name_idx = struct.unpack('<L', self.data[offset + (i * 8) + 4:offset + (i * 8) + 8])[0]


            proto_full_name=self.get_proto(proto_idx)
            # class_type_str=self.__type_ids[class_idx]['type_str']
            # if 'L' not in class_type_str or ';' not in class_type_str: #在有限的认知下, 该类型一定是一个 class 类, 后来发现类不一定是L开头, ';'结尾
            #     raise Exception('proto_str error')
            met_proto_split=proto_full_name.index(" ") # str.find()找不到返回-1, index会抛出异常
            ret_type_str=proto_full_name[:met_proto_split]
            arg_type_str=proto_full_name[met_proto_split+1:]#不从空格开始
            full_method_str=ret_type_str + " " + self.get_type(class_idx) + "." + self.get_str(name_idx)  + arg_type_str

            field_mem={
                'class_idx': class_idx,
                'proto_idx': proto_idx,
                'name_idx': name_idx,
                # 自定义
                'full_method_str': full_method_str
            }
            methods.append(field_mem)
            self.sig_cost.emit(i / method_ids_len)# 进度展示

        self.Dex['method_ids']['content']=methods
        self.Dex['method_ids']['loaded']=True

        self.sig_cost.emit(1)  # 100% 进度展示
        return methods





    def init_classdef_ids(self):
        """Get class definition data from DEX file

        :returns: list of class definition data extracted from class_def_item

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.init_classdef_ids()
            [
                {
                    'class_idx': 3049,
                    'access_flags': 4000,
                    'superclass_idx': 200,
                    'interfaces_off': 343,
                    'source_file_idx': 3182,
                    'annotation_off': 343,
                    'class_data_off': 345,
                    'static_values_off': 8830
                },
                ...
            ]
        """
        if self.Dex['classdef_ids']['loaded']:
            return self.Dex['classdef_ids']['content']

        LOG.log_info(tag="dexparser", msg="init_classdef_ids")
        classdef_data = []
        offset = self.header_data['class_defs_off']

        struct_classdef_size=32
        classdef_ids_len=self.header_data['class_defs_size']
        for i in range(classdef_ids_len):
            tmp_idx=i*struct_classdef_size
            class_idx = struct.unpack('<L', self.data[offset + tmp_idx:offset + tmp_idx + 4])[0]
            access_flag = struct.unpack('<L', self.data[offset + tmp_idx + 4:offset + tmp_idx + 8])[0]
            superclass_idx = struct.unpack('<L', self.data[offset +tmp_idx + 8:offset + tmp_idx + 12])[0]
            interfaces_off = struct.unpack('<L', self.data[offset + tmp_idx + 12:offset + tmp_idx + 16])[0]
            source_file_idx = struct.unpack('<L', self.data[offset + tmp_idx + 16:offset + tmp_idx + 20])[0]
            annotation_off = struct.unpack('<L', self.data[offset + tmp_idx + 20:offset + tmp_idx + 24])[0]
            class_data_off = struct.unpack('<L', self.data[offset + tmp_idx + 24:offset + tmp_idx + 28])[0]
            static_values_off = struct.unpack('<L', self.data[offset + tmp_idx + 28:offset + tmp_idx + 32])[0]

            sorted_access = [i for i in disassembler.ACCESS_ORDER if i & access_flag] # 把属性拆开

            access_str=""
            if len(sorted_access)!=0:
                for i in range(len(sorted_access)):
                    flag=sorted_access[i]
                    access_str=access_str+disassembler.access_flag_classes[flag] + " "

            class_name=self.get_type(class_idx) + " "
            extend_str = ""
            if superclass_idx!=0:
                extend_str="extend "+self.get_type(superclass_idx) + " "

            interfaces_str = ""
            if interfaces_off!=0:
                interfaces_cnt=struct.unpack('<L', self.data[interfaces_off:interfaces_off+4])[0]
                start_idx=interfaces_off+4
                for i in range(interfaces_cnt):
                    interfaces_idx=struct.unpack('<H', self.data[start_idx + i*2 : start_idx + i*2 +2])[0]
                    interfaces_str=interfaces_str + self.get_type(interfaces_idx)
                    if i+1<interfaces_cnt:
                        interfaces_str=interfaces_str + ","
                interfaces_str="interface "+interfaces_str + " "

            fname_class = ""
            if source_file_idx!=0:
                fname_class="in "+self.get_str(source_file_idx) + " "

            full_class_name=access_str + \
                            class_name + \
                            extend_str + \
                            interfaces_str + \
                            fname_class
            cls_def_mem={
                'class_idx': class_idx,
                'access': access_flag,
                'superclass_idx': superclass_idx,
                'interfaces_off': interfaces_off,
                'source_file_idx': source_file_idx,
                'annotation_off': annotation_off,
                'class_data_off': class_data_off,
                'static_values_off': static_values_off,
                #自定义
                'full_class_name':full_class_name
            }
            classdef_data.append(cls_def_mem)
            self.sig_cost.emit(i / classdef_ids_len)# 进度展示

        self.Dex['classdef_ids']['content']=classdef_data
        self.Dex['classdef_ids']['loaded']=True


        self.sig_cost.emit(1)  # 100%进度展示
        return classdef_data
    def init_maplists(self):

        if self.Dex['maplists']['loaded']:
            return self.Dex['maplists']['content']

        LOG.log_info(tag="dexparser", msg="init_maplists")
        offset=self.header_data['map_off']
        maplist_len=struct.unpack('<L', self.data[offset:offset+4])[0]
        sizeof_struct_maplist=12
        start_idx=offset+4

        map_list=[]
        for i in range(maplist_len):
            section_type=struct.unpack('<H', self.data[start_idx+0+i*sizeof_struct_maplist:start_idx+2+i*sizeof_struct_maplist])[0]
            #unused=struct.unpack('<H', self.data[start_idx+2+i*sizeof_struct_maplist:start_idx+4+i*sizeof_struct_maplist])[0]
            section_size=struct.unpack('<L', self.data[start_idx+4+i*sizeof_struct_maplist:start_idx+8+i*sizeof_struct_maplist])[0]
            section_offset=struct.unpack('<L', self.data[start_idx+8+i*sizeof_struct_maplist:start_idx+12+i*sizeof_struct_maplist])[0]
            map_item={
                'section_type': section_type,
                'section_size': section_size,
                'section_offset': section_offset,
                'section_type_str': map_type(section_type)
            }
            map_list.append(map_item)
            self.sig_cost.emit(i / maplist_len)#进度展示

        self.Dex['maplists']['content']=map_list
        self.Dex['maplists']['loaded']=True


        self.sig_cost.emit(1)  # 100%进度展示
        return map_list
    def get_class_datas(self, offset):
        """Get class specific data from DEX file

        :param integer offset: class_idx offset value
        :returns: specific data of class

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.get_class_datas(offset=3022)
            {
                'static_fields': [
                    {
                        'diff': 30, 'access_flags': 4000
                    }
                ],
                'instance_fields': [
                    {
                        'diff': 32, 'access_flags': 4000
                    }
                ],
                'direct_methods': [
                    {
                        'diff': 30, 'access_flags': 4000, 'code_off': 384304
                    }
                ],
                'virtual_methods': [
                    {
                        'diff': 63, 'access_flags': 4000, 'code_off': 483933
                    }
                ]
            }
        """
        static_fields = []
        instance_fields = []
        direct_methods = []
        virtual_methods = []

        static_field_size, sf_size = uleb128_value(self.data, offset)
        offset += sf_size
        instance_field_size, if_size = uleb128_value(self.data, offset)
        offset += if_size
        direct_method_size, dm_size = uleb128_value(self.data, offset)
        offset += dm_size
        virtual_method_size, vm_size = uleb128_value(self.data, offset)
        offset += vm_size

        for i in range(static_field_size):
            field_idx_diff, access_flags, size = encoded_field(self.data, offset)
            if i == 0:
                diff = field_idx_diff
            else:
                diff += field_idx_diff

            static_fields.append({'diff': diff, 'access_flags': access_flags})
            offset += size

        for i in range(instance_field_size):
            field_idx_diff, access_flags, size = encoded_field(self.data, offset)
            if i == 0:
                diff = field_idx_diff
            else:
                diff += field_idx_diff

            instance_fields.append({'diff': diff, 'access_flags': access_flags})
            offset += size

        for i in range(direct_method_size):
            method_idx_diff, access_flags, code_off, size = encoded_method(self.data, offset)
            if i == 0:
                diff = method_idx_diff
            else:
                diff += method_idx_diff

            direct_methods.append({
                'diff': diff,
                'access_flags': access_flags,
                'code_off': code_off
            })
            offset += size

        for i in range(virtual_method_size):
            method_idx_diff, access_flags, code_off, size = encoded_method(self.data, offset)
            if i == 0:
                diff = method_idx_diff
            else:
                diff += method_idx_diff

            virtual_methods.append({
                'diff': diff,
                'access_flags': access_flags,
                'code_off': code_off
            })
            offset += size

        return {
            'static_fields': static_fields,
            'instance_fields': instance_fields,
            'direct_methods': direct_methods,
            'virtual_methods': virtual_methods
        }

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


class APKParser(object):
    """APK file format parser class
    :param string filedir: APK file path
    :param bytes fileobj: APK file object
    :param boolean deepscan: Scan all assets of APK file for detect adex file
    """

    def __init__(self, filedir=None, fileobj=None, deepscan=False):
        if not filedir and not fileobj:
            raise InsufficientParameterError('fileobj or filedir parameter required.')

        if filedir:
            if not os.path.isfile(filedir):#检查给定的路径是否指向一个普通的文件
                raise FileNotFoundError

            if not is_zipfile(filedir): #检查给定的路径是否指向一个zip文件
                raise IsNotAPKFileFormatError("{} is not an APK file format.".format(filedir))

            self.zfile = ZipFile(filedir)#打开zip文件

        if fileobj:
            if not is_zipfile(BytesIO(fileobj)):
                raise IsNotAPKFileFormatError("Invalid APK file format.")

            self.zfile = ZipFile(BytesIO(fileobj))

        self.dexfiles = {} #字典

        if deepscan:
            for filename in self.zfile.namelist():
                stream = self.zfile.read(filename)
                if len(stream) < 8:
                    continue

                if stream[0:4] == "dex\x0a":
                    self.dexfiles[filename] = DEXParser(fileobj=stream)

        else:
            for filename in self.zfile.namelist():
                if filename.endswith(".dex"):
                    self.dexfiles[filename] = DEXParser(fileobj=self.zfile.read(filename))

    @property
    def is_multidex(self):
        """Detect if APK is a multidex
        https://developer.android.com/studio/build/multidex

        :returns: boolean

        example:
            >>> APKParser(filedir='path/to/file.apk').is_multidex
            True
        """
        return len(self.dexfiles.keys()) > 1

    def get_dex(self, filename="classes.dex"):
        """Get dex file with DEX parsed object

        :params: name of dexfile (default: classes.dex)
        :returns: DEXParser object

        example:
            >>> APKParser(filedir='path/to/file.apk').get_dex()
            True
        """
        return self.dexfiles[filename]

    def get_all_dex_filenames(self):
        """Get all name of dex files
        :returns: list of dex filenames

        example:
            >>> APKParser(filedir='path/to/file.apk').get_all_dex_filenames()
            ['classes.dex', 'classes1.dex']
        """
        return list(self.dexfiles.keys())


class AABParser(APKParser):
    """AAB (Android App Bundle) file format parser class
    :param string filedir: AAB file path
    :param bytes fileobj: AAB file object
    :param boolean deepscan: Scan all assets of AAB file for detect adex file
    """
    pass


class DEXParser(Dexparser):
    """DEX file format parser subclass
    :param string filedir: DEX file path
    :param bytes fileobj: DEX file object
    """
    pass
