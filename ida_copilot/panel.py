from typing import Optional

import idaapi
from PyQt5 import QtWidgets
from langchain.callbacks.base import BaseCallbackHandler


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super(Singleton, cls).__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


class CopilotPanel(idaapi.PluginForm, metaclass=Singleton):
    def __init__(self):
        super().__init__()
        self.parent = None
        self.text_edit: Optional[QtWidgets.QTextEdit] = None

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QVBoxLayout(self.parent)

        self.text_edit = QtWidgets.QTextEdit()
        layout.addWidget(self.text_edit)

    def OnClose(self, form):
        pass

    def Show(self, **kwargs):
        return idaapi.PluginForm.Show(self, "IDA Copilot", options=idaapi.PluginForm.WOPN_PERSIST)


class CopilotPanelCallbackManager(BaseCallbackHandler):
    def on_text(self, text: str, **kwargs):
        panel = CopilotPanel()
        if panel.text_edit:
            panel.text_edit.append(text)


class ShowCopilotPanel(idaapi.action_handler_t):
    def __init__(self, panel):
        idaapi.action_handler_t.__init__(self)
        self.panel = panel

    def activate(self, ctx):
        self.panel.Show()

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
