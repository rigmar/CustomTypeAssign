import ida_idaapi
import ida_hexrays
import logging
import ida_kernwin
import ida_struct
import ida_typeinf
from collections import namedtuple
import re

DEBUG = False
if DEBUG:
    import pydevd_pycharm

from actions import HexRaysPopupAction, action_manager
from callbacks import hx_callback_manager

RecastLocalVariable = namedtuple('RecastLocalVariable', ['curr_ti', 'local_variable'])
RecastGlobalVariable = namedtuple('RecastGlobalVariable', ['curr_ti', 'global_variable_ea'])
RecastArgument = namedtuple('RecastArgument', ['curr_ti', 'arg_idx', 'func_ea', 'func_tinfo'])
RecastReturn = namedtuple('RecastReturn', ['curr_ti', 'func_ea'])
RecastStructure = namedtuple('RecastStructure', ['curr_ti', 'structure_name', 'field_offset'])

prefixes = ['unsigned', 'signed']

def parse_decl(tif,inputtype,flags=0,til=None):
    if len(inputtype) != 0 and inputtype[-1] != ';':
        inputtype = inputtype + ';'
    
    if ida_typeinf.parse_decl(tif,til,inputtype,flags) is not None:
        return True
    return False

def parse_input_type(decl):
    pointer_count = 0
    type_name = decl
    tail = None
    tif = ida_typeinf.tinfo_t()
    if ' ' in decl:
        match = re.search(r"(.*<.*>)(.*)",decl)
        if match:
            tail = match.groups()[1].strip()
            type_name = match.groups()[0].strip()
        elif decl.count(' ') == 1:
            type_name, tail = decl.split("")
        else:
            ida_kernwin.warning("During type applying error occured.\nIn type declaration '%s' too many spaces symbols."%decl)
            type_name = None
    
    if tail:
        pointer_count += tail.count('*')
    if type_name:
        while type_name[-1] == '*':
            pointer_count += 1
            type_name = type_name[:-1]
        if tif.get_named_type(None, type_name):
            for i in range(pointer_count):
                tif.create_ptr(tif)
    return tif
    

class CustomTypeAssignHandler(HexRaysPopupAction):
    
    hotkey = "shift-y"
    description = "Set custom type..."
    
    def activate(self, ctx):  # type: (ida_kernwin.action_activation_ctx_t) -> None
        if DEBUG:
            pydevd_pycharm.settrace('localhost', port=3333, stdoutToServer=True, stderrToServer=True, suspend=False)
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        vdui.get_current_item(ida_hexrays.USE_KEYBOARD)
        target = vdui.item
        if target:
            cfunc = vdui.cfunc
            ri = self.get_target_type(cfunc,target)
            if ri:
                type_decl = ida_kernwin.ask_str("%s"%ri.curr_ti.dstr(),10,"Please enter the type declaration")
                if type_decl and type_decl != ri.curr_ti.dstr():
                    tif = ida_typeinf.tinfo_t()
                    if not parse_decl(tif,type_decl,ida_typeinf.PT_SIL):
                        type_decl = type_decl.strip()
                        tif = parse_input_type(type_decl)
                    if not tif.empty():
                        if isinstance(ri, RecastLocalVariable):
                            vdui.set_lvar_type(ri.local_variable, tif)
                        elif isinstance(ri, RecastGlobalVariable):
                            ida_typeinf.apply_tinfo(ri.global_variable_ea, tif, ida_typeinf.TINFO_DEFINITE)
                        elif isinstance(ri,RecastStructure):
                            sid = ida_struct.get_struc_id(ri.structure_name)
                            if sid != ida_idaapi.BADADDR:
                                sptr = ida_struct.get_struc(sid)
                                mptr = ida_struct.get_member(sptr, ri.field_offset)
                                if mptr:
                                    rc = ida_struct.set_member_tinfo(sptr, mptr, ri.field_offset, tif,
                                                                 ida_struct.SET_MEMTI_MAY_DESTROY)
                                    if rc != 1:
                                        print("set_member_tinfo rc = %d" % rc)
                        vdui.refresh_view(True)
                    else:
                        ida_kernwin.warning("During type applying error occured.\nInput type declaration: '%s'." % type_decl)
    
    def check(self, hx_view):  # type: (ida_hexrays.vdui_t) -> bool
        if DEBUG:
            pydevd_pycharm.settrace('localhost', port=3333, stdoutToServer=True, stderrToServer=True, suspend=False)
        hx_view.get_current_item(ida_hexrays.USE_KEYBOARD)
        target = hx_view.item
        cfunc = hx_view.cfunc
        if self.get_target_type(cfunc,target) is not None:
            return True
        return False
        
    def get_target_type(self,cfunc,ctree_item):
        # type: (ida_hexrays.cfunc_t,ida_hexrays.ctree_item_t) -> namedtuple
        if ctree_item.citype == ida_hexrays.VDI_EXPR and ctree_item.it.is_expr():
            expression = ctree_item.e
            if expression.opname not in ('var', 'obj', 'memptr', 'memref'):
                return None
            
            if expression.op == ida_hexrays.cot_var:
                variable = cfunc.get_lvars()[expression.v.idx]
                curr_ti = variable.tif
                return RecastLocalVariable(curr_ti,variable)
            
            elif expression.op == ida_hexrays.cot_obj:
                return RecastGlobalVariable(expression.type,expression.obj_ea)

            elif expression.op == ida_hexrays.cot_memptr:
                struct_name = expression.x.type.get_pointed_object().dstr()
                struct_offset = expression.m
                return RecastStructure(expression.type, struct_name, struct_offset)
            
            elif expression.op == ida_hexrays.cot_memref:
                struct_name = expression.x.type.dstr()
                struct_offset = expression.m
                return RecastStructure(expression.type, struct_name, struct_offset)
            
        elif ctree_item.citype == ida_hexrays.VDI_LVAR:
            variable = ctree_item.l
            curr_ti = variable.tif
            return RecastLocalVariable(curr_ti, variable)
        return None
        

def register_actions():
    pass


class CustomTypeAssign(ida_idaapi.plugin_t):
    flags = 0
    comment = "Type assign for HexRays without \"bad\" characters filtration"
    help = "Type assign for HexRays without \"bad\" characters filtration"
    wanted_name = "MyPlugins:CustomTypeAssign"
    wanted_hotkey = ""

    @staticmethod
    def init():
        if DEBUG:
            pydevd_pycharm.settrace('localhost', port=3333, stdoutToServer=True, stderrToServer=True, suspend=False)
        if not ida_hexrays.init_hexrays_plugin():
            logging.error("Failed to initialize Hex-Rays SDK")
            return ida_idaapi.PLUGIN_SKIP
        
        action_manager.register(CustomTypeAssignHandler())
        action_manager.initialize()
        hx_callback_manager.initialize()
        return ida_idaapi.PLUGIN_KEEP
        

    @staticmethod
    def term():
        hx_callback_manager.finalize()
        action_manager.finalize()
    
    @staticmethod
    def run():
        pass
    
def PLUGIN_ENTRY():
    logging.basicConfig(format='[%(levelname)s] %(message)s\t(%(module)s:%(funcName)s)')
    logging.root.setLevel(0)
    return CustomTypeAssign()