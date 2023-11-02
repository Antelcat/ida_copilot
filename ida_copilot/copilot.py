import asyncio
import concurrent.futures
import re
from typing import Any, Optional

from langchain.agents import tool, initialize_agent, AgentType
from langchain.callbacks import FileCallbackHandler
from langchain.callbacks.base import BaseCallbackManager
from langchain.callbacks.manager import CallbackManagerForToolRun
from langchain.chat_models import ChatOpenAI

import idaapi
from langchain.tools import BaseTool

from ida_copilot import core, prompts


class Copilot:
    def run(self, temperature=0.2, model='gpt-3.5-turbo-0613'):
        ea = idaapi.get_screen_ea()
        func_name = idaapi.get_func_name(ea)

        tools = [
            self.__GetAddressInfoTool(),
            self.__GetDefinitionTool(),
            self.__GetPseudocodeTool(),
            self.__SetFunctionCommentTool(),
            self.__SetFunctionDefinitionTool(),
            self.__SetFunctionNameTool(),
            self.__GetIsMyWorkDoneTool(ea)
        ]

        agent = initialize_agent(
            agent_type=AgentType.OPENAI_MULTI_FUNCTIONS,
            llm=ChatOpenAI(temperature=temperature, model=model),
            tools=tools,
            callback_manager=BaseCallbackManager(handlers=[
                # CopilotPanelCallbackManager(),
                FileCallbackHandler("G:\\output.log")]),
            verbose=True,
        )

        prompt = prompts.default_prompt_zh.format(
            binary_description=f'A function in .sys driver, name: {func_name}, address 0x{ea:x}'
            # pseudocode=pseudocode
        )

        # 开启新线程运行agent
        t = concurrent.futures.ThreadPoolExecutor()
        loop = asyncio.get_event_loop()
        loop.run_in_executor(t, agent.run, prompt)

    class __GetAddressInfoTool(BaseTool):
        name = 'get_address_info'
        description = ('Given a hex address or function name, show its information. '
                       '**Input Format**: `<hex_address_or_function_name>`. '
                       '**Input Example1**: `sub_140007080`. '
                       '**Input Example2**: `0x140007080`.')

        @staticmethod
        def __get_address_info(name_or_hex_address: str):
            try:
                if name_or_hex_address.lower().startswith('0x'):
                    ea = int(name_or_hex_address, 16)
                else:
                    ea = idaapi.get_name_ea(idaapi.BADADDR, name_or_hex_address)
                    if ea == idaapi.BADADDR:
                        raise Exception
            except Exception:
                return f'{name_or_hex_address} is not a valid address or name.'

            flags = idaapi.get_flags(ea)
            result = ''

            # 检查地址是否位于函数内部
            func = idaapi.get_func(ea)
            if func:
                result += "Address 0x%X is inside a function.\n" % ea
                result += "Function start: 0x%X\n" % func.start_ea
                result += "Function end: 0x%X\n" % func.end_ea
                func_name = idaapi.get_func_name(func.start_ea)
                if func_name:
                    result += "Function name: %s\n" % func_name
            elif idaapi.is_code(flags):
                result += "Address 0x%X is code.\n" % ea
            elif idaapi.is_data(flags):
                result += "Address 0x%X is data.\n" % ea
                if idaapi.is_byte(flags):
                    result += "Data type: Byte\n"
                    result += "Value: %d\n" % idaapi.get_wide_byte(ea)
                elif idaapi.is_word(flags):
                    result += "Data type: Word\n"
                    result += "Value: %d\n" % idaapi.get_wide_word(ea)
                elif idaapi.is_dword(flags):
                    result += "Data type: Dword\n"
                    result += "Value: %d\n" % idaapi.get_wide_dword(ea)
                elif idaapi.is_qword(flags):
                    result += "Data type: Qword\n"
                    result += "Value: %d\n" % idaapi.get_qword(ea)
                elif idaapi.is_float(flags):
                    result += "Data type: Float\n"
                    # result += "Value: %f\n" % idaapi.get_wide_float(address)
                elif idaapi.is_double(flags):
                    result += "Data type: Double\n"
                    # result += "Value: %f\n" % idaapi.get_wide_double(address)
                elif idaapi.is_strlit(flags):
                    result += "Data type: String\n"
                    result += "Value: %s\n" % idaapi.get_strlit_contents(ea)
                elif idaapi.is_struct(flags):
                    result += "Data type: Struct\n"
                # ... 其他数据类型检查
            elif idaapi.is_unknown(flags):
                result += "Address 0x%X is unknown.\n" % ea

            # 名称和注释
            if idaapi.has_name(flags):
                result += "Name: %s\n" % idaapi.get_name(ea)
            elif idaapi.has_dummy_name(flags):
                result += "Dummy name: %s\n" % idaapi.get_name(ea)

            if idaapi.has_cmt(flags):
                result += "Comment: %s\n" % idaapi.get_cmt(ea, 0)

            if result == '':
                result = 'Address not found.'
            elif result[-1] == '\n':
                result = result[:-1]

            return result

        def _run(self, query: str, run_manager: Optional[CallbackManagerForToolRun] = None) -> Any:
            query = core.escape_agent_input(
                query, 'get_address_info')

            return core.pop_async_call_result(
                idaapi.execute_sync(
                    lambda: core.push_async_call_result(self.__get_address_info(query)),
                    idaapi.MFF_WRITE))

    class __GetDefinitionTool(BaseTool):
        name = 'get_definition'
        description = ('Given a function name, show its definition. '
                       'NOTICE that the result is decompiled by IDA, so it may NOT be accurate. '
                       '**Input Format**: `<function_name>`. '
                       '**Input Example**: `sub_140007080`.')

        @staticmethod
        def __get_definition(function_name: str):
            try:
                return core.decompile_by_name(function_name).definition
            except Exception as e:
                return f'Failed to decompile: {e}'
            
        def _run(self, query: str, run_manager: Optional[CallbackManagerForToolRun] = None) -> Any:
            query = core.escape_agent_input(query, 'get_definition')

            return core.pop_async_call_result(
                idaapi.execute_sync(
                    lambda: core.push_async_call_result(self.__get_definition(query)), 
                    idaapi.MFF_WRITE))

    class __GetPseudocodeTool(BaseTool):
        name = 'get_pseudocode'
        description = ('Given a function name or hex address of a function, show its pseudocode. '
                       'NOTICE that the result is decompiled by IDA, so it may NOT be accurate. '
                       '**Input Format**: `<function_name_or_hex_address>`. '
                       '**Input Example1**: `sub_140007080`. '
                       '**Input Example2**: `0x140007080`.')

        @staticmethod
        def __get_pseudocode(function_name_or_hex_address: str):
            try:
                if function_name_or_hex_address.lower().startswith('0x'):
                    ea = int(function_name_or_hex_address, 16)
                    return core.decompile_by_ea(ea).pseudocode

                return core.decompile_by_name(function_name_or_hex_address).pseudocode
            except Exception as e:
                return f'Failed to decompile: {e}'

        def _run(self, query: str, run_manager: Optional[CallbackManagerForToolRun] = None) -> Any:
            query = core.escape_agent_input(
                query, 'get_pseudocode')

            return core.pop_async_call_result(
                idaapi.execute_sync(
                    lambda: core.push_async_call_result(self.__get_pseudocode(query)),
                    idaapi.MFF_WRITE))

    class __SetFunctionCommentTool(BaseTool):
        name = 'set_function_comment'
        description = ('Given a function name and a comment, set the comment of the function. '
                       '**Input Format**: `<function_name> <comment>`. '
                       '**Input Example**: `sub_140007080 Copilot Comment: This function is used to do something.`')

        @staticmethod
        def __set_function_comment(function_name_and_comment: str):
            try:
                func_name, comment = function_name_and_comment.split(' ', 1)
                func_name = func_name.strip()

                if not comment.startswith('Copilot Comment:'):
                    comment = 'Copilot Comment: ' + comment.strip()
                core.decompile_by_name(func_name).comment = comment

                return f'Successfully set comment of {func_name} to {comment}.'
            except Exception as e:
                return f'Failed to set comment: {e}'

        def _run(self, query: str, run_manager: Optional[CallbackManagerForToolRun] = None) -> Any:
            query = core.escape_agent_input(
                query, 'set_function_comment')

            return core.pop_async_call_result(
                idaapi.execute_sync(
                    lambda: core.push_async_call_result(self.__set_function_comment(query)),
                    idaapi.MFF_WRITE))

    class __SetFunctionDefinitionTool(BaseTool):
        name = 'set_function_definition'
        description = ('Set definition of a function. '
                       '**Input Format**: `<return_type> [calling_convention] <function_name>(<param_type> [param_name], ...)`. '
                       '**Input Example1**: `void sub_140005048(int a1, unsigned long long a2)`. '
                       '**Input Example2**: `NTSTATUS __fastcall DriverIoControl(PDRIVER_OBJECT, PIRP)`.')

        @staticmethod
        def __set_function_definition(new_definition: str):
            func_pattern = re.compile(
                r'(?P<ret_type>[\w\s*]+?)\s*(?P<cc>__\w+\s+)?(?P<func_name>\w+)\((?P<params>.*)\)')
            # param_pattern = re.compile(r'(\w+\s*\*?)\s*(\w+)')

            try:
                match = func_pattern.match(new_definition)
                if not match:
                    return f'Invalid function definition, not match: {new_definition}'

                result = match.groupdict()
                return_type = result['ret_type'].strip() if result['ret_type'] else None
                if not return_type:
                    return f'Invalid function definition, no return type: {new_definition}'

                # 上面的正则会漏掉一种情况
                # 例如，`NTSTATUSsub_140005048(PDRIVER_OBJECT driverObject, PIRP irp)`
                # 解析后，`ret_type`为`N`，`func_name`为`TSTATUSsub_140005048`
                # 因此我们要把这种输入列为无效输入
                if ' ' not in new_definition[:new_definition.index('(')]:
                    return f'Invalid function definition, no func name: {new_definition}'

                func_name = result['func_name'].strip()
                core.decompile_by_name(func_name).definition = new_definition

                return f'Successfully set definition of {func_name} to {new_definition}.'
            except Exception as e:
                return f'Failed to set definition: {e}'

        def _run(self, query: str, run_manager: Optional[CallbackManagerForToolRun] = None) -> Any:
            query = core.escape_agent_input(
                query, 'set_function_definition')

            return core.pop_async_call_result(
                idaapi.execute_sync(
                    lambda: core.push_async_call_result(self.__set_function_definition(query)),
                    idaapi.MFF_WRITE))

    class __SetFunctionNameTool(BaseTool):
        name = 'set_function_name'
        description = ('Given a function name, rename it. '
                       '**Input Format**: <old_name> <new_name>. '
                       '**Input Example**: sub_140007080 DeviceIoControl.')

        @staticmethod
        def __set_function_name(old_name_and_new_name: str):
            try:
                old_name, new_name = old_name_and_new_name.split(' ')
                old_name = old_name.strip()
                core.decompile_by_name(old_name).name = new_name

                return f'Successfully renamed {old_name} to {new_name}.'
            except Exception as e:
                return f'Failed to set function name: {e}'

        def _run(self, query: str, run_manager: Optional[CallbackManagerForToolRun] = None) -> Any:
            return core.pop_async_call_result(
                idaapi.execute_sync(
                    lambda: core.push_async_call_result(self.__set_function_name(query)),
                    idaapi.MFF_WRITE))

    class __GetIsMyWorkDoneTool(BaseTool):
        name = 'get_is_my_work_done'
        description = ('Given a function name, return whether the work is done. '
                       'Also return tips if not done.')
        func: Optional[core.DecompiledFunction] = None

        def __init__(self, current_func_ea, **kwargs: Any):
            super().__init__(**kwargs)
            self.func = core.decompile_by_ea(current_func_ea)

        def __get_is_my_work_done(self):
            try:
                for function in self.func.functions:
                    ea = function['ea']
                    func_name = idaapi.get_func_name(ea)
                    if func_name.startswith('sub_'):
                        return (f'No, function `{func_name}` at 0x{ea:x} is not renamed yet. Please continue your work.'
                                f'REMEMBER, your goal is to rename all functions that start with `sub_`.'
                                f'AND, your are analyzing function `{self.func.name}`.')

                return f'Yes, function `{self.func.name}` is fully analyzed.'

            except Exception as e:
                return f'Failed to get is my work done: {e}'

        def _run(self, query: str, run_manager: Optional[CallbackManagerForToolRun] = None) -> Any:
            return core.pop_async_call_result(
                idaapi.execute_sync(
                    lambda: core.push_async_call_result(self.__get_is_my_work_done()),
                    idaapi.MFF_WRITE))
