from collections import defaultdict
import ida_hexrays

from CustomTypeAssign import DEBUG
if DEBUG:
    import pydevd_pycharm
    

class HexRaysCallbackManager(object):
    def __init__(self):
        self.__hexrays_event_handlers = defaultdict(list)

    def initialize(self):
        ida_hexrays.install_hexrays_callback(self.__handle)

    def finalize(self):
        ida_hexrays.remove_hexrays_callback(self.__handle)

    def register(self, event, handler):
        self.__hexrays_event_handlers[event].append(handler)

    def __handle(self, event, *args):
        if DEBUG:
            pydevd_pycharm.settrace('localhost', port=3333, stdoutToServer=True, stderrToServer=True,suspend=False)
        for handler in self.__hexrays_event_handlers[event]:
            handler.handle(event, *args)
        # IDA expects zero
        return 0


hx_callback_manager = HexRaysCallbackManager()


class HexRaysEventHandler(object):
    def __init__(self):
        super(HexRaysEventHandler, self).__init__()

    def handle(self, event, *args):
        raise NotImplementedError("This is an abstract class")
