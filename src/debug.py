import gdb
from pprint import pprint

class KavaLocals(gdb.Command):
    """Prints the locals"""

    def __init__(self):
        super(KavaLocals, self).__init__(
            "kava-locals", gdb.COMMAND_USER
        )


    def complete(self, text, word):
        # We expect the argument passed to be a symbol so fallback to the
        # internal tab-completion handler for symbols
        return gdb.COMPLETE_SYMBOL

    def invoke(self, args, from_tty):
        frame = gdb.selected_frame()
        function = frame.function()
        file: str = function.symtab.filename
        [class_and_function, descriptor] = file.split('(')
        descriptor = "(" + descriptor
        class_and_function = class_and_function.removeprefix("cache/")
        point = class_and_function.rfind('.')
        clas = class_and_function[:point]
        clas = clas.replace('.', '/')
        descriptor = descriptor.replace('.', '/')
        meth = class_and_function[point + 1:]
        if meth == "_init_":
            meth = "<init>"
        elif meth == "_clinit_":
            meth = "<clinit>"


        print(clas, meth, descriptor)

        
        gdb.execute(f'call print_locals("{clas}", "{meth}", "{descriptor}", $rbp)') 
        

KavaLocals()
