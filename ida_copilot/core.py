import re

import ida_kernwin
import idautils
from fuzzywuzzy import process
from loguru import logger

import ida_hexrays
import idaapi

async_call_index = 0
async_call_stack = {}


def push_async_call_result(result):
    global async_call_index
    global async_call_stack

    async_call_stack[async_call_index] = result
    async_call_index += 1
    return async_call_index - 1


def pop_async_call_result(index):
    return async_call_stack.pop(index)


def preprocess_prompt(template: str) -> str:
    return re.sub(r'^[ \t]+', '', template, flags=re.MULTILINE).strip('\n')


def escape_agent_input(query: str, tool_name: str) -> str:
    """
    有时候Agent会错误地在输入中包括工具名
    比如应该输入`sub_140009000`，但是Agent会输入`tool_name('sub_140009000')`
    """
    logger.info(f'Escaping agent input: `{query}`')

    try:
        pattern = re.compile(rf'^{tool_name}\([\'"`](.+)[\'"`]\)$')
        match = pattern.match(query)
        if match:
            logger.info(f'Escaped agent input: `{query}` -> `{match.group(1)}`')
            return match.group(1)

        return query
    except Exception as e:
        logger.error(f'Failed to escape agent input: `{query}`')
        raise e


def get_screen_func():
    return idaapi.get_func(idaapi.get_screen_ea())


def get_safe_new_name(new_func_name: str) -> str:
    """
    检查new_func_name是否已存在，如果存在，递增处理
    :param new_func_name:
    :return:
    """
    if new_func_name[0].isdigit():
        new_func_name = 'fun_' + new_func_name

    existed_ea = idaapi.get_name_ea(idaapi.BADADDR, new_func_name)
    if existed_ea == idaapi.BADADDR:
        return new_func_name

    # 如果new_func_name最后有数字，递增处理
    match = re.match(r'^(.*?)(\d+)$', new_func_name)
    if match:
        prefix, suffix = match.groups()
        suffix = int(suffix)
    else:
        prefix = new_func_name
        suffix = 1

    while True:
        new_func_name = f'{prefix}{suffix}'
        existed_ea = idaapi.get_name_ea(idaapi.BADADDR, new_func_name)
        if existed_ea == idaapi.BADADDR:
            break
        suffix += 1

    return new_func_name


# 用于记录修改过的函数
# Copilot在一次分析的过程中并不会修改函数，而是记录下修改的内容，最后一次性修改。
# key: ea
# value: DecompiledFunction
decompiled_functions = dict()

renamed_functions = dict()
"""
记录重命名过的函数
有时候Copilot已经把一个函数重命名过了，但是Copilot在之后可能还使用了旧的函数名，这时候还需要能找到新的函数名。
WARN：只记录一次重命名。例如a -> b，那么现在根据a还能找到b。但如果又把c -> a，此时需要把a -> b删除。
key: old_name
value: new_name
"""


class DecompiledFunction:
    __cfunc: ida_hexrays.cfuncptr_t  # 反编译得到的函数

    def __init__(self, cfunc: ida_hexrays.cfuncptr_t):
        self.__cfunc = cfunc
        self.__refresh()

    def __hash__(self):
        return self.ea

    def __str__(self):
        return self.pseudocode

    def __refresh(self):
        self.__cfunc = idaapi.decompile(idaapi.get_func(self.ea), flags=ida_hexrays.DECOMP_NO_CACHE)
        self.__fix_func_types()
        self.__clean_up_local_variables()

        vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())
        if vdui:
            vdui.refresh_view(True)

    @property
    def ea(self) -> int:
        """函数地址"""
        return self.__cfunc.entry_ea

    @property
    def comment(self) -> str:
        """函数注释，例如`Copilot Comment: 这是一个函数`"""
        return idaapi.get_func_cmt(self.ea, True)

    @comment.setter
    def comment(self, new_comment: str):
        """设置函数注释"""
        idaapi.set_func_cmt(idaapi.get_func(self.ea), new_comment.strip(), True)
        self.__refresh()

    @property
    def name(self) -> str:
        """函数名，例如`sub_140009000`"""
        return idaapi.get_func_name(self.ea)

    @name.setter
    def name(self, new_name: str):
        """设置函数名"""
        new_name = new_name.strip()
        if new_name == self.name:
            raise Exception(f'`{new_name}` is same as current name')

        if new_name.startswith('sub_'):
            raise Exception(f'Function name should not start with `sub_`, which is a preserved name by IDA: `{new_name}`')

        old_name = self.name

        new_name = get_safe_new_name(new_name)
        idaapi.set_name(self.ea, new_name, idaapi.SN_CHECK)
        self.__refresh()

        renamed_functions.pop(new_name, None)
        renamed_functions[old_name] = new_name

    @property
    def definition(self) -> str:
        """函数签名，例如`__int64 __fastcall sub_140009000(__int64 a1, IRP *a2)`"""
        func_type = idaapi.tinfo_t()
        self.__cfunc.get_func_type(func_type)
        signature = str(func_type)  # signature不带函数名，需要加上
        signature = signature.replace('(', f' {self.name}(', 1).replace('  ', ' ')
        return signature

    @definition.setter
    def definition(self, new_signature: str):
        tinfo = idaapi.tinfo_t()
        idaapi.parse_decl(tinfo, None, new_signature + ';', idaapi.PT_TYP)
        if str(tinfo) == '':
            raise Exception(f'Invalid function definition, parse failed: `{new_signature}`')

        func_data = idaapi.func_type_data_t()
        if not tinfo.get_func_details(func_data):
            raise Exception(f'Invalid function definition: `{new_signature}`')

        original_tinfo = idaapi.tinfo_t()
        idaapi.get_tinfo(original_tinfo, self.ea)
        if str(original_tinfo) != '':
            original_func_details = idaapi.func_type_data_t()
            if original_tinfo.get_func_details(original_func_details):
                func_data.flags = original_func_details.flags

        tinfo.create_func(func_data)
        if str(tinfo) == '':
            raise Exception(f'Invalid function definition, create function type failed: {new_signature}')

        idaapi.apply_tinfo(self.ea, tinfo, idaapi.TINFO_DEFINITE)
        self.__refresh()

    @property
    def pseudocode(self) -> str:
        """反编译得到的伪代码"""
        return str(self.__cfunc)

    def __fix_func_types(self):
        """
        Fix the types of the function decompiled by IDA.
        根据当前反编译的函数调用参数类型修复目标函数签名。
        """
        logger.info(f'Fixing function types...{self.__cfunc.entry_ea:x}')

        called_functions = self.functions
        for func_info in called_functions:
            args = func_info['args']
            if len(args) == 0:
                continue  # Skip functions without arguments

            tinfo = func_info['tinfo']
            if str(tinfo) == '':
                continue  # Skip functions without signature

            ea = func_info['ea']

            # 修复函数签名
            # 例如，IDA推断的函数为`__int64 __fastcall sub_140009000()`，
            # 但是在反编译中，他被这样调用：
            # NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
            # {
            #   sub_1400090BC();
            #   return sub_140009000(DriverObject);
            # }
            # 这里的`sub_140009000`应该是`NTSTATUS __stdcall sub_140009000(PDRIVER_OBJECT DriverObject)`，
            # 因此我们需要修复函数签名。

            func_details = idaapi.func_type_data_t()
            if not tinfo.get_func_details(func_details):
                print(f'Failed to get function details of {ea:x}')
                continue

            new_func_details = idaapi.func_type_data_t()
            new_func_details.rettype = func_details.rettype
            new_func_details.cc = func_details.cc
            new_func_details.flags = func_details.flags

            for arg in args:
                func_arg = idaapi.funcarg_t()
                func_arg.type = arg.formal_type
                new_func_details.push_back(func_arg)

            new_tinfo = idaapi.tinfo_t()
            new_tinfo.create_func(new_func_details)
            logger.info(f'Fixing function type of 0x{ea:x}: {tinfo} -> {new_tinfo}')

            idaapi.apply_tinfo(ea, new_tinfo, idaapi.TINFO_DEFINITE)

    @staticmethod
    def __type_to_var_name(tinfo: idaapi.tinfo_t):
        """
        将类型信息转换为变量名（小写下划线命名法）
        """
        name = tinfo.dstr()
        parts = re.findall(r'[a-zA-Z0-9]+', name)

        if parts[0] == 'struct':
            parts = parts[1:]

        if len(parts) == 0:
            return 'v'

        name = '_'.join(parts).lower()
        if not name[0].isalpha():
            name = "v_" + name
        return name

    class __FunctionCallCollector(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.called_functions = []

        def visit_expr(self, e):
            if e.op == idaapi.cot_call:
                func_ea = e.x.obj_ea
                if func_ea != idaapi.BADADDR:
                    tinfo = idaapi.tinfo_t()
                    func_info = {'ea': func_ea, 'tinfo': tinfo, 'args': e.a}

                    if not idaapi.get_tinfo(tinfo, func_ea) and not idaapi.guess_tinfo(tinfo, func_ea):
                        # IDA无法推断函数签名，需要通过反编译获取
                        func = idaapi.decompile(idaapi.get_func(func_ea), flags=ida_hexrays.DECOMP_NO_CACHE)
                        func.get_func_type(tinfo)

                    self.called_functions.append(func_info)

            return 0  # Continue traversal

    @property
    def functions(self) -> list[dict]:
        """
        Get all called functions in the decompiled function.
        :return: [{'ea': func_ea, 'tinfo': tinfo, 'args': e.a}]
        """
        collector = DecompiledFunction.__FunctionCallCollector()
        collector.apply_to(self.__cfunc.body, None)
        return collector.called_functions

    def __clean_up_local_variables(self):
        """
        Clean up local variables in the decompiled function.
        清理反编译函数中的局部变量。
        包含函数参数中的变量，以及函数内部的局部变量。
        清理前：
        __int64 __fastcall sub_140007090(__int64 a1, IRP *a2)
        {
          __int64 v2; // r14
          unsigned int v3; // ebx
          struct _IO_STACK_LOCATION *v5; // rcx
          struct _IRP *v6; // rsi
          unsigned int v7; // edi
          ULONG_PTR v8; // r15
          unsigned int v9; // eax
          HANDLE v10; // rax
          HANDLE v11; // rax

        清理后：
        __int64 __fastcall sub_140007090(__int64 a1, IRP *irp)
        {
          __int64 v2; // r14
            unsigned int v3; // ebx
            struct _IO_STACK_LOCATION *io_stack_location0; // rcx
            struct _IRP *irp0; // rsi
            unsigned int v7; // edi
            ULONG_PTR v8; // r15
            unsigned int v9; // eax
            HANDLE handle0; // rax
            HANDLE handle1; // rax
        """
        lvars = self.__cfunc.get_lvars()
        var_mapping = {}
        used_names = set()

        for lvar in lvars:
            tinfo = lvar.type()
            base_name = DecompiledFunction.__type_to_var_name(tinfo)
            new_name = base_name
            suffix = 1
            while new_name in used_names:
                new_name = f"{base_name}_{suffix}"
                suffix += 1
            used_names.add(new_name)
            lvar.__name = new_name
            var_mapping[lvar.__name] = new_name

        # Update the cfunc
        self.__cfunc.build_c_tree()


def decompile_by_ea(ea: int) -> DecompiledFunction:
    decompiled_function = decompiled_functions.get(ea)
    if not decompiled_function:
        func = idaapi.get_func(ea)
        if not func:
            raise Exception(f'0x{ea:x} is not a function.')

        cfunc = idaapi.decompile(func, flags=ida_hexrays.DECOMP_NO_CACHE)
        decompiled_function = decompiled_functions[ea] = DecompiledFunction(cfunc)

    return decompiled_function


def decompile_by_name(name: str) -> DecompiledFunction:
    name = name.strip()
    functions = {idaapi.get_func_name(ea).strip(): ea for ea in idautils.Functions()}
    best_match = process.extractOne(name, functions.keys(), score_cutoff=50)
    if best_match:
        if best_match[0] == name:
            return decompile_by_ea(functions[best_match[0]])

        raise Exception(f'Function `{name}` not found. Did you mean `{best_match[0]}`?')

    renamed_name = renamed_functions.get(name)
    if renamed_name:
        ea = functions.get(renamed_name)
        if ea:
            return decompile_by_ea(ea)

    raise Exception(f'Function `{name}` not found.')
