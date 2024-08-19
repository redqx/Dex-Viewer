from dataclasses import dataclass
from inspect import isclass
from typing import Union, Any , TypeVar
from io import BytesIO
from _io import _BufferedIOBase
from ctypes import (
    c_char,
    sizeof as _sizeof,
    Array
)
from _ctypes import _SimpleCData

# ----------------------------------------------------------------------------
from packages.mm_type.mm_const import *
from packages.mm_type.mm_ctype import data_to_ctypes

_CData = tuple(x for x in c_char.mro() if x.__name__ == "_CData")[0]

class BaseStructure:
    """
    该类实现了结构体的基础方法。
    """

    def __init__(self,base_position=0, data: Union[bytes, _BufferedIOBase]=None) -> None:
        # 初始化类，data可以是字节流或文件流
        self._source = b""  # 用于存储读取的数据源
        if isinstance(data, bytes):
            # 如果data是字节流，将其转换为BytesIO对象，以便像文件一样读取
            data = BytesIO(data)

        # 遍历类的所有属性
        for attribute_name, attribute_value in self.__annotations__.items():
            start_position = data.tell()  # 记录当前的读取位置

            if issubclass(attribute_value, Array):
                # 如果属性是一个数组类型
                cClass = self.array_to_cclass(attribute_value)  # 获取数组中元素的C类型
                cClass_size = sizeof(cClass)  # 获取C类型的大小
                used_data = data.read(sizeof(attribute_value))  # 读取相应大小的数据
                self._source += used_data  # 将读取的数据存储到_source中
                # 使用读取的数据构建数组对象，并赋值给类的属性
                # value = attribute_value(
                #     *(
                #         data_to_ctypes[cClass](
                #             used_data[x * cClass_size : (x + 1) * cClass_size]
                #         )
                #         for x in range(attribute_value._length_)
                #     )
                # )
                # 创建一个空列表用于存放转换后的数据
                elements = []
                # 遍历数组的每个元素
                for x in range(attribute_value._length_):
                    # 提取当前元素的数据块
                    element_data = used_data[x * cClass_size: (x + 1) * cClass_size]

                    # 将数据块转换为对应的C类型对象
                    ctype_object = data_to_ctypes[cClass](element_data)

                    # 将转换后的对象添加到列表中
                    elements.append(ctype_object)

                # 使用转换后的列表来创建属性值
                value = attribute_value(*elements)

                setattr(self, attribute_name, value)
            elif issubclass(attribute_value, BaseStructure):
                # 如果属性是一个BaseStructure的子类
                used_data = data.read(sizeof(attribute_value))  # 读取相应大小的数据
                self._source += used_data  # 将读取的数据存储到_source中
                # 使用读取的数据构建子结构对象，并赋值给类的属性
                value = attribute_value(used_data)
                setattr(self, attribute_name, value)
            else:
                # 如果属性是其他类型
                cClass = self.class_to_cclass(attribute_value)  # 获取该类型的C类型
                used_data = data.read(sizeof(cClass))  # 读取相应大小的数据
                value = data_to_ctypes[cClass](used_data)  # bug 将读取的数据转换为对应的C类型对象
                self._source += used_data  # 将读取的数据存储到_source中
                setattr(self, attribute_name, value)  # 将值赋给类的属性

            # 记录读取数据的起始位置和结束位置
            value._data_ = used_data
            value._start_position_ = base_position + start_position
            value._end_position_ = base_position + data.tell()
        pass

    @classmethod
    def array_to_cclass(cls, array: Array) -> type:
        """
        返回数组元素对应的C类型。
        """
        return cls.class_to_cclass(array._type_)

    @staticmethod
    def class_to_cclass(cls: type) -> type:
        """
        返回该类的C类型（如果存在）。
        """
        precedent_class = None
        # 遍历类的继承链，找到继承的C类型
        for element in cls.mro():
            if element is _SimpleCData:
                return precedent_class
            precedent_class = element

    @classmethod
    def __sizeof__(cls) -> int:
        """
        返回构建实例所需的字节数。
        """
        counter = 0
        # 计算所有属性所占的内存大小
        for value in cls.__annotations__.values():
            counter += sizeof(value)
        return counter

    def __repr__(self):
        # 返回类名和数据源的字符串表示
        return self.__class__.__name__ + "(" + repr(self._source) + ")"

    def __str__(self):
        # 返回类名和所有属性的字符串表示
        return (
                self.__class__.__name__
                + "("
                + ", ".join(
            f"{attr}="
            + (
                (
                        getattr(self, attr).__class__.__name__
                        + f"({getattr(self, attr).value})"
                )
                if isinstance(getattr(self, attr), Array)
                else getattr(self, attr)
            )
            for attr in self.__annotations__
        )
                + ")"
        )


def sizeof(object: Union[_CData, type]) -> int:
    """
    This function returns the size of this object.
    """

    if isinstance(object, _CData) or issubclass(object, _CData):
        return _sizeof(object)
    return object.__sizeof__()


_issubclass = issubclass


def issubclass(test: Any, *args):
    """
    This function checks if the tested elements is a
    subclass of comparator.
    """

    if isclass(test):
        return _issubclass(test, *args)
    return False


@dataclass
class Field:
    """
    This class implements
    """

    value: Any
    information: str
    usage: str = None
    description: str = None


class FileString(str):
    """
    This class implements strings with positions
    (_start_position_ and _end_position_ attributes).
    """

    pass


class FileBytes(bytes):
    """
    This class implements bytes with positions
    (_start_position_ and _end_position_ attributes).
    """

    pass

Structure = TypeVar("Structure")
def read_file_from_struct(file: _BufferedIOBase, structure: type) -> Structure:
    """
    This function reads file and parse readed data
    to Structure and returns it.
    """
    base_pos = file.tell()
    data = file.read(sizeof(structure))
    return structure(base_pos,data)#这么传递进去,感觉不太对