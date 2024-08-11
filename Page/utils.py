def org2Hex(arg_value) -> str:
    """
    将一个 int 数值转换为小端序的 16 进制字符串表示。
    """
    retValue=""
    if type(arg_value).__name__ == "bytes":
        retValue = retValue + arg_value.hex().upper()
    elif type(arg_value).__name__ == 'int':
        byteLen=arg_value.bit_length() // 8
        if arg_value.bit_length()%8 !=0:
            byteLen=byteLen+1
        byte_seq = arg_value.to_bytes(length=byteLen , byteorder='little',signed=False)  #进来的参数默认无符号吧
        retValue = retValue + byte_seq.hex().upper()
        if (arg_value>>32)>0:
            retValue =  retValue.ljust(16, "0")
        else:
            retValue = retValue.ljust(8, "0")
    else:
        retValue = retValue + "error"
    return retValue

def man_show(arg_value):
    if type(arg_value).__name__ == "bytes":
        return str(arg_value)
    elif type(arg_value).__name__ == 'int':
        return str(arg_value)
    else:
        return "error"
def isDexFile(file_path):
    retValue=False

    check1=file_path.lower().endswith(".dex")
    check2=file_path.lower().endswith(".apk")

    f =open(file_path, 'rb')
    first_3_bytes = f.read(3).decode("utf-8",errors="ignore")
    f.close()
    check3= first_3_bytes == "dex"

    if check1 or check2 or check3:
        retValue=True
    return retValue
