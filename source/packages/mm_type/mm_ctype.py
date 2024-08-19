from functools import partial
from typing import Union

from ctypes import (
    c_bool,
    c_wchar,
    c_byte,
    c_ubyte,
    c_short,
    c_ushort,
    c_int,
    c_uint,
    c_long,
    c_ulong,
    c_longlong,
    c_size_t,
    c_ssize_t,
    c_float,
    c_double,
    c_longdouble,
    c_char_p,
    c_wchar_p,
    c_void_p,
    c_uint16,
    c_int32,
    c_ulonglong,
    c_int8,
    c_uint8,
    c_int16,
    c_uint32,
    c_int64,
    c_uint64,
    c_char,
)
from _ctypes import _SimpleCData

class DataToCClass:
    """
    This class implements methods to get ctypes from data.
    """

    order: str = "little"

    def data_to_bytes(
            type: type, data: Union[bytes, int, str]
    ) -> _SimpleCData:
        """
        This method converts bytes, int or str to ctypes (c_char, c_char_p).
        """

        if isinstance(data, int):
            data = data.to_bytes()
        elif isinstance(data, str):
            data = data.encode("latin-1")

        return type(data[::-1] if DataToCClass.order == "little" else data)

    def data_to_int(arg_type: type, data: Union[bytes, int, None]) -> _SimpleCData:
        """
        This method converts bytes, int or None to ctypes
        (c_bool, c_byte, c_ubyte, c_short, c_ushort, c_int,
        c_uint, c_long, c_ulong, c_longlong, c_ulonglong,
        c_size_t, c_ssize_t, c_void_p, c_int8, c_int16,
        c_int32, c_int64, c_uint8, c_uint16, c_uint32,
        c_uint64).
        """

        if isinstance(data, bytes):
            if DataToCClass.order == "little":
                data = int.from_bytes(data, byteorder="little")
                #data=data[::-1]
            else:
                data = int.from_bytes(data, byteorder="big")
        return arg_type(data)

    def data_to_str(
            type: type, data: Union[bytes, str], encoding: str = "utf-8"
    ) -> _SimpleCData:
        """
        This method converts bytes or str to ctypes (c_wchar, c_wchar_p).
        """

        if isinstance(data, bytes):
            data = data.decode(encoding)

        return type(data)

    def data_to_float(type: type, data: Union[bytes, float]) -> _SimpleCData:
        """
        This method converts bytes or float to ctypes
        (c_float, c_double, c_longdouble).
        """

        if isinstance(data, bytes):
            data = float.fromhex(
                (data[::-1] if DataToCClass.order == "little" else data).hex()
            )

        return type(data)


data_to_ctypes = {
    c_bool: partial(DataToCClass.data_to_int, c_bool),
    c_char: partial(DataToCClass.data_to_bytes, c_char),
    c_wchar: partial(DataToCClass.data_to_str, c_wchar),
    c_byte: partial(DataToCClass.data_to_int, c_byte),
    c_int8: partial(DataToCClass.data_to_int, c_int8),
    c_ubyte: partial(DataToCClass.data_to_int, c_ubyte),
    c_uint8: partial(DataToCClass.data_to_int, c_uint8),
    c_short: partial(DataToCClass.data_to_int, c_short),
    c_int16: partial(DataToCClass.data_to_int, c_int16),
    c_ushort: partial(DataToCClass.data_to_int, c_ushort),
    c_uint16: partial(DataToCClass.data_to_int, c_uint16),
    c_int: partial(DataToCClass.data_to_int, c_int),
    c_int32: partial(DataToCClass.data_to_int, c_int32),
    c_uint: partial(DataToCClass.data_to_int, c_uint),
    c_uint32: partial(DataToCClass.data_to_int, c_uint32),
    c_long: partial(DataToCClass.data_to_int, c_long),
    c_ulong: partial(DataToCClass.data_to_int, c_ulong),
    c_longlong: partial(DataToCClass.data_to_int, c_longlong),
    c_int64: partial(DataToCClass.data_to_int, c_int64),
    c_ulonglong: partial(DataToCClass.data_to_int, c_ulonglong),
    c_uint64: partial(DataToCClass.data_to_int, c_uint64),
    c_size_t: partial(DataToCClass.data_to_int, c_size_t),
    c_ssize_t: partial(DataToCClass.data_to_int, c_ssize_t),
    c_float: partial(DataToCClass.data_to_float, c_float),
    c_double: partial(DataToCClass.data_to_float, c_double),
    c_longdouble: partial(DataToCClass.data_to_float, c_longdouble),
    c_char_p: partial(DataToCClass.data_to_bytes, c_char_p),
    c_wchar_p: partial(DataToCClass.data_to_str, c_wchar),
    c_void_p: partial(DataToCClass.data_to_int, c_void_p),
}
