import sys
import os

current_path = os.path.dirname(__file__)

egg_loc = os.path.join(current_path, "pycharm-debug.egg")
sys.path.append(egg_loc)
print egg_loc
import pydevd



import PyQt5.QtGui as QtGui
import PyQt5.QtCore as QtCore
import PyQt5.QtWidgets as QtWidgets
import idaapi
import idautils
import idc
import json
import sip

with open(current_path + "/dict.json", "r") as read_file:
    DICT = json.load(read_file)
ID_NA = "."




# -----------------------------------------------------------------------------



class TakeAttributes():
    def __init__(self, ea, name, dst, risk):
        self.ea = ea
        self.name = name
        self.dst = dst
        self.risk = risk


# -----------------------------------------------------------------------------
class XrefTable(Choose2):
    def __init__(self, title):

        columns = [["Caller", 20 | 327680], ["Function", 30 | 327680], ["NumOfArgs", 8], ["Risk", 8]]
        # columns += [[i, 8] for i in ARG_NAMES]
        Choose2.__init__(self, title, columns)
        self.items = []
        twidget = idaapi.find_widget("Functions window")
        self.widget = sip.wrapinstance(long(twidget), QtWidgets.QWidget)  # NOTE: LOL
        self.table = self.widget.findChild(QtWidgets.QTableView)
        self.table.selectionModel().selectionChanged.connect(self.my_event)

    def OnClose(self):
        self.items = []

    def OnSelectLine(self, n):
        jumpto(self.items[n][0])

    def OnGetLine(self, n):
        return self._make_choser_entry(n)

    def OnGetSize(self):
        n = len(self.items)
        return n

    def feed(self, data, caller=None):
        for item in data:
            call = idc.get_func_off_str(item.ea)
            for temp in caller:
                if temp in call:
                    full_list = [item.ea, item.name, str(item.dst), str(item.risk)]
                    self.items.append(full_list)
                    break
        self.Refresh()
        return

    def my_event(self):
        func_list = []
        self.items = []
        for name in DICT:
            func_list += get_callers(str(name))
            func_list += get_callers("_" + str(name))

        func_list = set(func_list)

        CALLER_LIST = self.get_selected_funcs()
        for ea in func_list:
            try:
                cfunc = idaapi.decompile(ea)
            except idaapi.DecompilationFailure:
                print "Error decompiling function @ 0x%x" % ea
                cfunc = None

            if cfunc:
                fp = func_parser_t(cfunc)
                fp.apply_to(cfunc.body, None)
                self.feed(fp.data, CALLER_LIST)

    def _make_choser_entry(self, n):
        dst = []
        dst += ["%s" % idc.get_func_off_str(self.items[n][0])]
        dst += ["%s" % self.items[n][1]]
        for i in range(2, len(self.items[n])):
            dst += [self.items[n][i]]
        #print dst
        return dst

    def get_selected_funcs(self):
        selected_funcs = [str(s.data()) for s in self.table.selectionModel().selectedRows()]

        return selected_funcs


# -----------------------------------------------------------------------------
class func_parser_t(idaapi.ctree_visitor_t):
    def __init__(self, cfunc):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.cfunc = cfunc
        self.data = []
        return

    def _add_func_call(self, func_info):
        self.data.append(func_info)
        return

    def _parse_function(self, e):
        args = e.a  # carglist_t

        dst_name = idaapi.tag_remove(e.print1(None))

        numOfArgs = args.size()
        risk = ""
        for trisk in DICT[idaapi.tag_remove(e.x.print1(None))]:
            if str(numOfArgs) == trisk:
                risk = DICT[idaapi.tag_remove(e.x.print1(None))][trisk]
                break

        self._add_func_call(TakeAttributes(e.ea, dst_name, numOfArgs, risk))
        return True

    def visit_expr(self, e):
        op = e.op
        # if expression type is call
        if op == idaapi.cot_call:
            name = idaapi.tag_remove(e.x.print1(None))
            # print "name func = %s" % name
            # and if the function name is supported
            if name in DICT:
                # parse
                self._parse_function(e)
        return 0



    # -----------------------------------------------------------------------------


def is_ida_version(requested):
    rv = requested.split(".")
    kv = idaapi.get_kernel_version().split(".")

    count = min(len(rv), len(kv))
    if not count:
        return False

    for i in xrange(count):
        if int(kv[i]) < int(rv[i]):
            return False
    return True


# -----------------------------------------------------------------------------
def get_callers(name):
    for xr in idautils.CodeRefsTo(idaapi.get_name_ea(idaapi.BADADDR, name), True):
        fn = idaapi.get_func(xr)
        if fn:
            yield fn.startEA


# -----------------------------------------------------------------------------

class Xrefs(idaapi.plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"

    help = "This is help"
    wanted_name = "XrefTable"
    wanted_hotkey = ""#"Alt-F8"

    def init(self):
        #
        idaapi.load_plugin('hexrays')
        idaapi.msg("init() called!\n")


        return idaapi.PLUGIN_OK

    def run(self, arg):
        idaapi.msg("run() called with %d!\n" % arg)
        if not idaapi.init_hexrays_plugin():
            print "This script requires the HexRays decompiler plugin."
        else:

            #dict = {'myfunc':[{'args':'2', 'risk':'2 (medium)'}, {'args':'3', 'risk':'1 (low)'}], 'memset': {{'args':'2', 'risk':'2 (medium)'}}}
            Table = XrefTable("XrefTable")
            Table.Show()


    def term(self):
        return



def PLUGIN_ENTRY():
    return Xrefs()
'''
dict_template = {'dword ptr [esp]': [0x401500]}

for reg in dict_template.keys():
    for addr in dict_template.get(reg):
        print ("Addr log func:0x%08x\n" % addr)
        total = 0
        resolve = 0
        for xref in idautils.XrefsTo(addr, idaapi.XREF_ALL):
            print (xref.frm)
            if idaapi.isCode(GetFlags(xref.frm)):
                print ("cool")
                total +=1
                ea_call = xref.frm

                func_start = idc.GetFunctionAttr(ea_call, idc.FUNCATTR_START)

                if not func_start or func_start == idc.BADADDR:
                    print ("Func don't define: 0x%08x" % (ea_call))
                    continue

                ea = ea_call
                strFname = ""
                #Backtrace
                while ea != idc.BADADDR and ea != func_start:
                    ea = idc.PrevHead(ea, func_start)
                    print("ea = %x " % ea)
                    print (idc.GetMnem(ea))
                    print ("%s = %s" % (idc.GetOpType(ea, 0), idc.o_phrase))
                    print ("%s = %s" % (idc.GetOpnd(ea, 0), reg))
                    print ("%s = %s" % (idc.GetOpType(ea, 1), idc.o_imm))
                    print ("-----------------")

                    if idc.GetMnem(ea) == "mov" and idc.GetOpType(ea,0) ==idc.o_phrase \
                            and idc.GetOpnd(ea,0) == reg and idc.GetOpType(ea, 1) == idc.o_imm:
                        strFname = GetString(GetOperandValue(ea,1))
                        #print ("We found it = %s" % GetString(GetOperandValue(ea,1)))
                        #break
                        print("strFname = %s" % strFname)
                        if strFname is not None:

                            predName = GetFunctionName(func_start)
                            if predName.startswith('sub_'):
                                if idc.MakeName(func_start, strFname):
                                    print ("Addr: 0x%08x Before: %s After: %s" % (xref.frm,predName,strFname))
                                else:
                                    strFname = str(strFname) + "_"+ str(func_start)
                                    idc.MakeName(func_start,strFname)
                                    print ("Addr: 0x%08x Before: %s After: %s" % (xref.frm, predName, strFname))

                                resolve +=1
                                break
                            else:
                                print ("[Error] Conflict! current name: %s new_name: %s" %(predName,strFname))
                                break
                        else:
                            print ("[ERROR] Problem with string!")
                            break
        print ("%d/%d" % (resolve, total))'''