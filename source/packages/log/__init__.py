class LOG:
    @staticmethod
    def log_info(tag: str = "info", msg: str = ""):  # green
        text = f"\033[92m[{tag}]\033[0m: {msg}"
        print(text)

    @staticmethod
    def log_error(tag: str = "error", msg: str = ""):  # red
        text = f"\033[91m[{tag}]\033[0m: {msg}"
        print(text)