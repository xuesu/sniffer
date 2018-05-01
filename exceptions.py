class MyException(Exception):
    def __init__(self, *args):
        super(MyException, self).__init__(*args)
        self.message = "Internal Error."


class UnableListAllDevicesError(MyException):
    def __init__(self, err_buff):
        super(UnableListAllDevicesError, self).__init__()
        self.message = "Unable to List Devices. {}".format(err_buff)


class UnableOpenDeviceError(MyException):
    def __init__(self, err_buff, name):
        super(UnableOpenDeviceError, self).__init__()
        self.message = "Unable to Open Devices {}. {}".format(name, err_buff)


class UnableSetFilterError(MyException):
    def __init__(self, err_buff, filter_str):
        super(UnableSetFilterError, self).__init__()
        self.message = "Unable to Set Filter {}. {}".format(filter_str, err_buff)


class ReadError(MyException):
    def __init__(self, num=None):
        super(ReadError, self).__init__()
        if num is None:
            self.message = "Unable to Read Next Packet".format(num)
        else:
            self.message = "Unable to Read No.{} Packet".format(num)


class ThreadUnInitializedError(MyException):
    def __init__(self):
        super(ThreadUnInitializedError, self).__init__()
        self.message = "This thread haven't been properly initialized."
