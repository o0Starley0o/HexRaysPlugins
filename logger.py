# import sys
# import os
#
# current_path = os.path.dirname(__file__)
#
# egg_loc = os.path.join(current_path, "pycharm-debug.egg")
# sys.path.append(egg_loc)
# print egg_loc
# import pydevd


import PyQt5.QtCore as QtCore
import PyQt5.QtWidgets as QtWidgets
import idaapi
import idautils
import idc
function_list = ["sub_401500", "sub_401560"]


class FunctionList(idaapi.PluginForm):
    def __init__(self):
        super(FunctionList, self).__init__()
        self.parent = None
        self.table = QtWidgets.QTableWidget()
        self.le = QtWidgets.QLineEdit()
        self.le.move(130, 22)
        self.main_data = []



    def OnCreate(self, form):
        self.parent = idaapi.PluginForm.FormToPyQtWidget(form)
        self.parent.setStyleSheet(
            "QTableWidget {background-color: transparent; selection-background-color: #87bdd8;}"
            "QHeaderView::section {background-color: transparent; border: 0.7px solid;}"
            "QPushButton {width: 50px; height: 20px;}"
        )
        self.parent.resize(400, 600)
        self.parent.setWindowTitle('Renamer')

        self.table.setStyleSheet(
            "QHeaderView::section{Background-color:rgb(190,1,1); border - radius:14px;}"
            "QTableWidget {background-color: #FFFFFF; selection-background-color: #000000;}"
        )
        self.table.setColumnCount(3)
        self.table.setRowCount(1)
        self.table.setHorizontalHeaderLabels(["LOG FUNCTION", "CALL", "POTENTIAL NAME"])
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.cellDoubleClicked.connect(self.cellDoubleClicked)

        btn_ADD = QtWidgets.QPushButton("&ADD")
        btn_RENAME = QtWidgets.QPushButton("&RENAME")
        btn_SHOW = QtWidgets.QPushButton("&SHOW")

        grid_box = QtWidgets.QGridLayout()
        grid_box.setSpacing(0)
        grid_box.addWidget(btn_ADD, 0, 0)
        grid_box.addWidget(btn_SHOW, 0, 1)
        grid_box.addWidget(btn_RENAME, 0, 2)
        grid_box.addItem(QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Expanding), 0, 5)
        grid_box.addItem(QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Expanding), 1, 5)
        vertical_box = QtWidgets.QVBoxLayout()
        vertical_box.addWidget(self.table)
        vertical_box.addLayout(grid_box)
        self.parent.setLayout(vertical_box)

        btn_ADD.clicked.connect(self.buildExamplePopup)
        btn_SHOW.clicked.connect(self.feed)
        btn_RENAME.clicked.connect(self.rename)

    def OnClose(self, form):
        pass

    def feed(self):
        names_of_calls = []
        self.main_data = []
        self.table.setRowCount(0)
        global function_list
        for name in function_list:
            names_of_calls += self.get_callers(str(name))

        for ea in names_of_calls:
            try:
                cfunc = idaapi.decompile(ea)
            except idaapi.DecompilationFailure:
                print "Error decompiling function @ 0x%x" % ea
                cfunc = None

            if cfunc:
                fp = func_parser_t(cfunc)
                fp.apply_to(cfunc.body, None)
                self._make_choser_entry(ea, fp.data)

        self.numrows = len(self.main_data)
        self.numcols = len(self.main_data[0])
        for i in self.main_data:
            if len(i) > self.numcols:
                self.numcols = len(i)

        self.table.setColumnCount(self.numcols+1)
        self.table.setRowCount(self.numrows)
        columns = ["LOG FUNCTION", "CALL"]
        columns += ["arg "+str(i) for i in range(1, self.numcols-1)]
        columns += ["POTENTIAL NAME"]
        self.table.setHorizontalHeaderLabels(columns)


        for row in range(self.numrows):
            for column in range(self.numcols):
                try:
                    self.table.setItem(row, column, QtWidgets.QTableWidgetItem((self.main_data[row][column])))
                    if self.main_data[row][column] != ".":
                        self.table.setItem(row, self.numcols, QtWidgets.QTableWidgetItem((self.main_data[row][column])))
                except:
                    self.table.setItem(row, column, QtWidgets.QTableWidgetItem("."))
                self.table.item(row, column).setFlags(QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled)
        return


    def rename (self):
        for row in range(self.numrows):
            if str(self.table.model().index(row, self.numcols).data()) == '.':
                print "Function \"{}\" not renamed".format(str(self.table.model().index(row, 1).data()))
            else:
                func_adress = idaapi.get_name_ea(idaapi.BADADDR, str(self.table.model().index(row, 1).data()))
                idc.MakeName(func_adress, str(self.table.model().index(row, self.numcols).data()))
                print "Function \"{}\" renamed to \"{}\" successfully".format(str(self.table.model().index(row, 1).data()), str(self.table.model().index(row, self.numcols).data()))

    def cellDoubleClicked(self, row, column):
        if (column > 1) & (column < (self.table.columnCount()-1)):
            self.table.setItem(row, self.numcols, QtWidgets.QTableWidgetItem((self.table.model().index(row, column).data())))
        elif column <= 1:
            jumpto(idaapi.get_name_ea(idaapi.BADADDR, str(self.table.model().index(row, column).data())))

    def Show(self, caption=None, options=0):
        return idaapi.PluginForm.Show(self, caption, options=options)

    def buildExamplePopup(self):
        self.exPopup = examplePopup()
        self.exPopup.show()

    def get_callers(self, name):
        for xr in idautils.CodeRefsTo(idaapi.get_name_ea(idaapi.BADADDR, name), True):
            fn = idaapi.get_func(xr)
            if fn:
                yield fn.startEA

    def _make_choser_entry(self, ea, data):
        for item in data:
            full_list = [item.name, idc.get_func_off_str(ea)]
            for i in item.dst:
                full_list += [i]
            self.main_data.append(full_list)
        return



class examplePopup(QtWidgets.QWidget):
    def __init__(self):
        super(examplePopup, self).__init__()

        self.initUI()

    def initUI(self):
        self.resize(250, 250)
        self.center()
        self.setWindowTitle("Enter log func")
        global function_list

        self.lblName = QtWidgets.QPlainTextEdit(self)
        for i in function_list:
            self.lblName.insertPlainText(str(i)+'\n')
        self.btnOK = QtWidgets.QPushButton("OK", self)
        vertical_box = QtWidgets.QVBoxLayout(self)
        vertical_box.addWidget(self.lblName)
        vertical_box.addWidget(self.btnOK)
        self.btnOK.clicked.connect(self.btnOk_clicked)


    def center(self):
        qr = self.frameGeometry()
        cp = QtWidgets.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def btnOk_clicked(self):
        global function_list
        function_list = []
        data = self.lblName.toPlainText()
        function_list += data.split("\n")
        self.close()


class TakeAttributes():
    def __init__(self, ea, name, dst):
        self.ea = ea
        self.name = name
        self.dst = dst


class func_parser_t(idaapi.ctree_visitor_t):
    def __init__(self, cfunc):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.cfunc = cfunc
        self.data = []
        return

    def _add_func_call(self, func_info):
        self.data.append(func_info)
        return

    def _parse_memcpy(self, e):
        args = e.a

        dst_name = []
        for i in args:
            if idc.GetString(i.obj_ea, -1, idc.ASCSTR_C) is not None:
                dst_name += [idc.GetString(i.obj_ea, -1, idc.ASCSTR_C)]
            else:
                dst_name += ["."]

        name = idaapi.tag_remove(e.x.print1(None))

        self._add_func_call(TakeAttributes(e.ea, name, dst_name))
        return True

    def visit_expr(self, e):
        op = e.op
        if op == idaapi.cot_call:
            name = idaapi.tag_remove(e.x.print1(None))
            if name in function_list:
                self._parse_memcpy(e)
        return 0


class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"

    help = "This is help"
    wanted_name = "Renamer"
    wanted_hotkey = "Alt-F8"

    def init(self):
        idaapi.load_plugin('hexrays')
        idaapi.msg("init() called!\n")

        return idaapi.PLUGIN_OK

    def run(self, arg):
        #pydevd.settrace('localhost', port=12345, stdoutToServer=True, stderrToServer=True)
        if not idaapi.init_hexrays_plugin():
            print "This script requires the HexRays decompiler plugin."
        else:
            Table = FunctionList()
            Table.Show()


    def term(self):
        return


def PLUGIN_ENTRY():
    return myplugin_t()
