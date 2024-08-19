

#目前还不知道是否能真正的update
def update_dict(arg_dict: dict, arg_strKey: str, arg_value):
    if arg_strKey in arg_dict:
        return update_dict(arg_dict, arg_strKey + "$", arg_value)
    if len(arg_strKey)==0:
        return update_dict(arg_dict, "$", arg_value)
    else:
        arg_dict[arg_strKey]=arg_value
