import ida_hexrays
import ida_kernwin
import idaapi

from ida_copilot import panel
from ida_copilot.copilot import Copilot


class CopilotPluginActionHandler(idaapi.action_handler_t):
    def __init__(self):
        super(CopilotPluginActionHandler, self).__init__()

    def activate(self, ctx):
        ida_kernwin.show_wait_box('HIDECANCEL\nRunning Copilot...')
        try:
            Copilot().run()
        finally:
            ida_kernwin.hide_wait_box()
            ida_hexrays.get_widget_vdui(ctx.widget).refresh_view(True)
            ida_kernwin.refresh_idaview_anyway()


    def on_task_complete(self, future):
        # 关闭进度条或状态信息
        ida_kernwin.hide_wait_box()

        # 更新UI...
        ida_kernwin.refresh_idaview_anyway()

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class CopilotPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Copilot"
    help = "Copilot"
    wanted_name = "Copilot"
    wanted_hotkey = ""

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            print("Hex-Rays decompiler is not available!")
            return

        run_action = idaapi.action_desc_t(
            'copilot:run',
            'Run Copilot',
            CopilotPluginActionHandler(),
            'Ctrl+Shift+P',
            '使用Copilot分析当前函数',
            -1)
        idaapi.register_action(run_action)
        idaapi.attach_action_to_menu(
            'Edit/Copilot',
            'copilot:run',
            idaapi.SETMENU_APP)

        action_desc = idaapi.action_desc_t(
            'copilot:show_panel',
            'Show Copilot',
            panel.ShowCopilotPanel(panel.CopilotPanel()),
            None,
            'Copilot integration',
            0
        )
        idaapi.register_action(action_desc)

        # 添加菜单项
        idaapi.attach_action_to_menu(
            'Windows/Copilot',
            'copilot:show_panel',
            idaapi.SETMENU_APP)

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.require('ida_copilot')
        print('Copilot reloaded')

    def term(self):
        idaapi.detach_action_from_menu(
            'Edit/Copilot',
            'copilot:run')
        idaapi.unregister_action('copilot:run')

        idaapi.detach_action_from_menu(
            'Windows/Copilot',
            'copilot:show_panel')
        idaapi.unregister_action('copilot:show_panel')


def PLUGIN_ENTRY():
    return CopilotPlugin()
