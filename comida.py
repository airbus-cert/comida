"""
This plugin is designed to target Malware analyst and Windows internal reverser

It try to find all reference of GUID by matching then with registry values
and list all references with function name to quickly navigate by COM references

Then if you have Hex-Rays plugin, it will infer type for result of 
* CoCreateInstance function
* CoGetCallContext function
* QueryInterface method

To facilitate work of analyst.
It will try to find type by quering debug name of the GUID interface
"""

import idaapi
import idautils
import idc
import sys
import winreg
import struct
import functools
from PyQt5 import QtCore, QtWidgets, QtGui

__author__ = "Airbus CERT"

class ComIDA(idaapi.ida_idaapi.plugin_t):
    """
    This is the main plugin class
    """
    comment = ""
    help = ""
    flags = idaapi.PLUGIN_MOD
    wanted_name = 'ComIDA'
    wanted_hotkey = 'Ctrl-Shift-M'
    hxehook = None

    def init(self):
        """
        Init plugin function
        """
        if idc.get_inf_attr(idc.INF_FILETYPE) != idc.FT_PE:
            # skip if it's not a PE
            return idaapi.PLUGIN_SKIP
        ComIDA.log("'%s' loaded. %s activates/deactivates synchronization." % (ComIDA.wanted_name, ComIDA.wanted_hotkey))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        Launch when you press Ctrl-Shift-M
        """
        if idaapi.init_hexrays_plugin():
            if not ComIDA.hxehook:
                ComResultsForm(find_com_references()).show()
                ComIDA.hxehook = ComIdaHook()
                ComIDA.hxehook.hook()
            else:
                ComIDA.hxehook.unhook()
                ComIDA.hxehook = None

        ComIDA.log("%s is %sabled now." % (ComIDA.wanted_name, "en" if ComIDA.hxehook else "dis"))

    def term(self):
        ComIDA.log("%s unloaded." % (ComIDA.wanted_name))
        if idaapi.init_hexrays_plugin() and ComIDA.hxehook:
            ComIDA.hxehook.unhook()
            ComIDA.hxehook = None
            
    def log(message):
         idaapi.msg("[%s] %s\n" % (ComIDA.wanted_name, message))

def check_binary_is_pe():
    """
    Check if we are currently working on a valid PE module
    """
    return idc.get_inf_attr(idc.INF_FILETYPE) == idc.FT_PE


def guid_bytes_to_string(stream):
    """
    Read a byte stream to parse as GUID
    :ivar bytes stream: GUID in raw mode
    :returns: GUID as a string
    :rtype: str
    """
    Data1 = struct.unpack("<I", stream[0:4])[0]
    Data2 = struct.unpack("<H", stream[4:6])[0]
    Data3 = struct.unpack("<H", stream[6:8])[0]
    Data4 = stream[8:16]

    return "%08x-%04x-%04x-%s-%s" % (Data1, Data2, Data3, "".join("%02x" % x for x in Data4[0:2]), "".join("%02x" % x for x in Data4[2:]))


class COMModule:
    """
    Class represent a COM module
    It's defined by GUID name a module path
    """
    def __init__(self, ea, guid, name, module, where):
        """
        :ivar int ea: address of data value
        :ivar str guid: global identifier of COM object
        :ivar str name: name of the com object
        :ivar str name: path of a module in charge of it
        :ivar str where: interface or class string
        """
        self.ea = ea
        self.guid = guid
        self.name = name
        self.module = module
        self.where = where

       
def build_com_from_class_definition(ea, guid):
    """
    Build a COM module object from class definition into registry
    :ivar int operand_value: data reference value
    :returns: new COM definition
    :rtype: COMModule
    :raise: WindowsError
    """
    
    key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "CLSID\\{%s}"%guid)
    _, name, _ = winreg.EnumValue(key, 0)
    module = "Not Found"
    try:
        inprocserver32 = winreg.OpenKey(key, "InprocServer32")
        _, module, _ = winreg.EnumValue(inprocserver32, 0)
    except WindowsError:
        pass
        
    return COMModule(ea, guid, name, module, "class")


def build_com_from_interface_definition(ea, guid):
    """
    Build a com module object from Interface class definition into registry
    :ivar int operand_value: data reference value
    :returns: new COM definition
    :rtype: COMModule
    :raise: WindowsError
    """
    
    key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "Interface\\{%s}"%guid)
    _, name, _ = winreg.EnumValue(key, 0)
    return COMModule(ea, guid, name, "N/A", "interface")

    
def find_guid_in_address_space(start_address, end_address):
    """
    This function will try to parse memonique with an operand value as second
    parameter, then will try to validate it with registry
    :ivar int start_address: 
    """
    result = []
    for head in idautils.Heads(start_address, end_address):
        # search for direct value operand
        operand_value = idc.get_operand_value(head, 1)
        guid_bytes = idc.get_bytes(operand_value, 16)
        guid = guid_bytes_to_string(guid_bytes)
        try:
            result.append(build_com_from_class_definition(head, guid))
        except WindowsError as e:
            pass
            
        try:
            result.append(build_com_from_interface_definition(head, guid))
        except WindowsError as e:
            pass
            
    return result

  
def find_com_references():
    """
    This function will try to find data references that match GUIDs
    and return a list of COMModule object with function name
    :return: list of tuble (function_name, COMMOdule)
    :rtype: tuple(str, COMModule)
    """
    result = []
    for seg in idautils.Segments():
        for funcea in idautils.Functions(seg, idc.get_segm_end(seg)):
            result += [(idaapi.ida_funcs.get_func_name(funcea), x) for x in find_guid_in_address_space(funcea, idc.find_func_end(funcea))]       
                
    return result


@functools.lru_cache(maxsize=None)
def find_import(module, function_name):
    """
    Find import address of a function by module name and function name
    :ivar str module: module name
    :ivar str function_name: name of the function from the module
    :returns: address of function
    """
    nimps = idaapi.get_import_module_qty()
    for i in range(0, nimps):
        if idaapi.get_import_module_name(i) != module:
            continue
        ea_ref = [None]
        def find_ea(ea, name, ord):
            if name == function_name:
                ea_ref[0] = ea
                return False
            return True
        idaapi.enum_import_names(i, find_ea)
        return ea_ref[0]
    return None


def infer_function_signature(cfunc, expr, index_interface, index_output):
    """
    This function will infer type of variable present at index_output
    in function signature by type found in registry in accordance 
    to the GUID set at the index_interface
    :ivar cfunc_t cfunc: function object that is decompiling
    :ivar cexpr_t expr: IDA expression AST
    :ivar int index_interface: index of the GUID parameter into function signature
    :ivar int index_output: index of the output variable that will be infer
    """
    variable = expr.a[index_output].v
    # check if variable is a ref to a variable
    if expr.a[index_output].op == idaapi.cot_ref:
        variable = expr.a[index_output].x.v

    if variable is None:
        ComIDA.log("Variable name not found")
        return False 
    
    ComIDA.log("infer type of variable: (%s)"%cfunc.lvars[variable.idx].name)
    # try to find type name from third parameter
    guid_bytes = idc.get_bytes(idc.get_operand_value(expr.a[index_interface].ea, 1), 16)
    guid = guid_bytes_to_string(guid_bytes)
    
    interface = None
    try:
        interface = build_com_from_interface_definition(expr.a[index_interface].ea, guid)
    except WindowsError as e:
        ComIDA.log("Interface type (%s) not found"%guid)   
        
    tinfo = idaapi.tinfo_t()
    if interface is None or not tinfo.get_named_type(idaapi.get_idati(), interface.name):
        ComIDA.log("type (%s) not found in registry switch to symbol name base heuristic"%guid)
        symbol_name = idc.get_name(idc.get_operand_value(expr.a[index_interface].ea, 1))
        if symbol_name is None or not tinfo.get_named_type(idaapi.get_idati(), symbol_name[4:]):
            ComIDA.log("unable to find type for (%s)"%guid)
            return False
        
    cfunc.get_lvars()[variable.idx].set_final_lvar_type(idaapi.make_pointer(tinfo))
    return True


class CoFunctionTypeInference(idaapi.ctree_visitor_t):
    """
    This is the visitor class use to visit all note of Hex Rays AST
    This visitor is designed to find call of functions that handle output from interface guid
    
    Before:
        LPVOID v19[2];
        int v1;
        CoCreateInstance(&CLSID_WbemBackupRestore, 0i64, v1, &IID_IWbemBackupRestoreEx, v2);
        
        (*(void (__fastcall **)(LPVOID))(*(_QWORD *)v2[0] + 40i64))(v2[0]);
    
    After:
        IWbemBackupRestoreEx *v19;
        int v1;
        CoCreateInstance(&CLSID_WbemBackupRestore, 0i64, v1, &IID_IWbemBackupRestoreEx, (LPVOID *)&v2);
        
        ((void (__fastcall *)(IWbemBackupRestoreEx *))v2->lpVtbl->Pause)(v2);
    """
    def __init__(self, cfunc, ea_function, index_interface, index_output):
        """
        :ivar cfunc_t cfunc: code function provided by IDA
        :ivar int ea_function: address of the function
        :ivar int index_interface: index of the argument that specify COM interface GUID
        :ivar int index_output: index of the function argument that will be infered in accordance to the GUID
        """
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.cfunc = cfunc
        self.ea_function = ea_function
        self.need_update = False
        self.index_interface = index_interface
        self.index_output = index_output

    def visit_expr(self, i):
        if i.op != idaapi.cot_call:
            return 0
        
        if i.x.obj_ea != self.ea_function:
            return 0

        self.need_update = infer_function_signature(self.cfunc, i, self.index_interface, self.index_output)
        return 0
            
    
    def is_updated(self):
        return self.need_update


class CoMethodTypeInference(idaapi.ctree_visitor_t):
    """
    This visitor is designed to find QueryInterface method calling
    It will find AST pattern ppv->Vtble->QueryInterface
    This must be check after all other inferering method
    """
    def __init__(self, cfunc, method_name, index_interface, index_output):
        """
        :ivar cfunc_t cfunc: code function provided by IDA
        :ivar int ea_function: address of the function
        :ivar int index_interface: index of the argument that specify COM interface GUID
        :ivar int index_output: index of the function argument that will be infered in accordance to the GUID
        """
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.cfunc = cfunc
        self.method_name = method_name
        self.need_update = False
        self.index_interface = index_interface
        self.index_output = index_output

    def visit_expr(self, i):
        if i.op != idaapi.cot_call:
            return 0

        node = i.x
        if node.op == idaapi.cot_cast:
            node = node.x
        
        if node.op != idaapi.cot_memptr:
            return 0
        
        offset = node.m
        node = node.x
        
        type = node.type.get_pointed_object()
        if type is None:
            return 0

        member = idaapi.udt_member_t()
        member.offset = offset * 8
        
        type.find_udt_member(member, idaapi.STRMEM_OFFSET)
        
        if member.name != self.method_name:
            return 0
        
        self.need_update = infer_function_signature(self.cfunc, i, self.index_interface, self.index_output)
        return 0 
    
    def is_updated(self):
        return self.need_update


def infers_cocreateinstance_variable(cfunc):
    """
    Try infering last variable of CoCreateInstance function
    by checking the GUID of interface and try to find type with same name
    
    :ivar cfunc_t cfunc: Hex-Ray code function
    """
    # Find address of CoCreateInstance
    # Due to ApiScheme redirect need to check both
    ea_cocreateinstance = find_import("ole32", "CoCreateInstance") or find_import("api-ms-win-core-com-l1-1-0", "CoCreateInstance")
    
    if ea_cocreateinstance is None:
        ComIDA.log("There is no references to CoCreateInstance")
        return
        
    v = CoFunctionTypeInference(cfunc, ea_cocreateinstance, 3, 4)
    
    v.apply_to(cfunc.body, None)
    if v.is_updated():
        cfunc.build_c_tree()
        

def infers_cogetcallccontext_variable(cfunc):
    """
    Try infering last variable of CoGetCallContext function
    by checking the GUID of interface and try to find type with same name
    
    :ivar cfunc_t cfunc: Hex-Ray code function
    """
    # Find address of CoGetCallContext
    # Due to ApiScheme redirect need to check both
    ea_cogetcallcontext = find_import("ole32", "CoGetCallContext") or find_import("api-ms-win-core-com-l1-1-0", "CoGetCallContext")
    
    if ea_cogetcallcontext is None:
        ComIDA.log("There is no references to CoGetCallContext")
        return
        
    v = CoFunctionTypeInference(cfunc, ea_cogetcallcontext, 0, 1)
    
    v.apply_to(cfunc.body, None)
    if v.is_updated():
        cfunc.build_c_tree()


def infers_queryinterface_variable(cfunc):
    """
    It will try to infer var by checking QueryInterface call method
    :ivar cfunc_t cfunc: Code function generate by Hex-Rays plugin
    """ 
    v = CoMethodTypeInference(cfunc, "QueryInterface", 1, 2)
    
    v.apply_to(cfunc.body, None)
    if v.is_updated():
        cfunc.build_c_tree()

def infers_com(cfunc):
    """
    Found refreneces to CoCreateInstance function and infere type of last variable
    in accordance of GUID of third parameter
    :ivar cfunc_t cfunc: Code function generate by Hex-Rays plugin
    """
    infers_cocreateinstance_variable(cfunc)
    infers_cogetcallccontext_variable(cfunc)
    # must be at the to use other infering method
    infers_queryinterface_variable(cfunc)
    
       
class ComIdaHook(idaapi.Hexrays_Hooks):
    """
    Install Hex Rays hooks on decompilation
    """
    def __init__(self):
        super().__init__()
        self.prevent_rec = False
    def maturity(self, cfunc, new_maturity):
        """
        This callback is used by decompilator at every step of processing
        """
        if self.prevent_rec:
            return 0
        self.prevent_rec = True
        # We work at the final maturity
        if new_maturity == idaapi.CMAT_FINAL:
            infers_com(cfunc)
        self.prevent_rec = False
        return 0


class ComResultsModel(QtCore.QAbstractTableModel):
    """
    This class is QT class that help to view data from COM parsing
    """
    COL_NAME = 0x00
    COL_FUNCTION = 0x01
    COL_ADDRESS = 0x02
    COL_GUID = 0x03
    COL_COM_TYPE = 0x04
    COL_MODULE = 0x05
    
    def __init__(self, com_module, parent=None):
        super().__init__(parent)

        self._column_headers = {
            ComResultsModel.COL_NAME : 'Name',
            ComResultsModel.COL_ADDRESS : 'Address',
            ComResultsModel.COL_FUNCTION : 'Function',
            ComResultsModel.COL_GUID : 'GUID',
            ComResultsModel.COL_COM_TYPE : 'Object type',
            ComResultsModel.COL_MODULE : 'Module'
        }
        
        self._results = list(com_module)
        self._row_count = len(self._results)

    def flags(self, index):
        return QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable

    def rowCount(self, index=QtCore.QModelIndex()):
        return self._row_count

    def columnCount(self, index=QtCore.QModelIndex()):
        return len(self._column_headers)

    def headerData(self, column, orientation, role=QtCore.Qt.DisplayRole):
        """
        Define the properties of the the table rows & columns.
        """
        if orientation == QtCore.Qt.Horizontal:

            # the title of the header columns has been requested
            if role == QtCore.Qt.DisplayRole:
                try:
                    return self._column_headers[column]
                except KeyError as e:
                    pass

            # the text alignment of the header has beeen requested
            elif role == QtCore.Qt.TextAlignmentRole:

                # center align all columns
                return QtCore.Qt.AlignHCenter

        # unhandled header request
        return None

    def data(self, index, role=QtCore.Qt.DisplayRole):
        """
        Define how Qt should access the underlying model data.
        """
        # data display request
        if role == QtCore.Qt.DisplayRole:

            # grab for speed
            row = index.row()
            column = index.column()

            if column == ComResultsModel.COL_ADDRESS:
                return "0x%x" % self._results[row][1].ea
            elif column == ComResultsModel.COL_FUNCTION:
                return self._results[row][0]
            elif column == ComResultsModel.COL_NAME:
                return self._results[row][1].name
            elif column == ComResultsModel.COL_GUID:
                return self._results[row][1].guid
            elif column == ComResultsModel.COL_COM_TYPE:
                return self._results[row][1].where
            elif column == ComResultsModel.COL_MODULE:
                return self._results[row][1].module

        # font color request
        elif role == QtCore.Qt.ForegroundRole:
            return QtGui.QColor(QtCore.Qt.black)

        # unhandeled request, nothing to do
        return None
        

class ComResultsForm(idaapi.PluginForm):
    """
    Form that display a table of all COM object found in binary
    """
    def __init__(self, com_modules):

        super().__init__()
        self.com_modules = com_modules
    
    def OnCreate(self, form):
        """
        Initialize the custom PyQt5 content on form creation.
        """

        # Get parent widget
        self._widget  = self.FormToPyQtWidget(form)

        self._init_ui()

    def show(self):
        """
        Make the created form visible as a tabbed view.
        """
        flags = idaapi.PluginForm.WOPN_TAB | idaapi.PluginForm.WOPN_PERSIST 
        return idaapi.PluginForm.Show(self, "COM", flags)

    
    def _init_ui(self):
        """
        Init ui of COM table
        """
        self._model = ComResultsModel(self.com_modules, self._widget)
        self._table = QtWidgets.QTableView()

        # set these properties so the user can arbitrarily shrink the table
        self._table.setMinimumHeight(0)
        self._table.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Ignored
        )

        self._table.setModel(self._model)

        # jump to disassembly on table row double click
        self._table.doubleClicked.connect(self._ui_entry_double_click)

        # set the initial column widths for the table
        #self._guess_column_width()

        # table selection should be by row, not by cell
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        # more code-friendly, readable aliases
        vh = self._table.verticalHeader()
        hh = self._table.horizontalHeader()
        vh.setSectionResizeMode(QtWidgets.QHeaderView.Fixed)

        # hide the vertical header themselves as we don't need them
        vh.hide()

        # Allow multiline cells
        self._table.setWordWrap(True) 
        self._table.setTextElideMode(QtCore.Qt.ElideMiddle);
        self._table.resizeColumnsToContents()
        self._table.resizeRowsToContents()

        layout = QtWidgets.QGridLayout()
        layout.addWidget(self._table)
        self._widget.setLayout(layout)

    def _ui_entry_double_click(self, index):
        """
        If user double click it jump to the COM ea
        :ivar int index: index of table
        """
        idaapi.jumpto(self._model._results[index.row()][1].ea)

            
def PLUGIN_ENTRY(): 
    return ComIDA()
