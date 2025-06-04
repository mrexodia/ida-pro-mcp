from __future__ import annotations

from PyQt5.QtWidgets import (
    QDockWidget,
    QWidget,
    QVBoxLayout,
    QTextEdit,
    QLineEdit,
    QToolBar,
    QAction,
    QProgressBar,
)
from PyQt5.QtCore import Qt


class MCPDock(QDockWidget):
    """Simple dock widget for interacting with the MCP core."""

    def __init__(self, plugin, parent=None) -> None:
        super().__init__("MCP", parent)
        self.plugin = plugin

        self.history = QTextEdit()
        self.history.setReadOnly(True)

        self.prompt = QLineEdit()

        self.toolbar = QToolBar()
        self.send_action = QAction("Send", self)
        self.clear_action = QAction("Clear", self)
        self.toolbar.addAction(self.send_action)
        self.toolbar.addAction(self.clear_action)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setMaximum(0)

        self.send_action.triggered.connect(self.on_send)
        self.clear_action.triggered.connect(self.history.clear)
        self.prompt.returnPressed.connect(self.on_send)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.addWidget(self.history)
        layout.addWidget(self.prompt)
        layout.addWidget(self.toolbar)
        layout.addWidget(self.progress)
        self.setWidget(central)

    def on_send(self) -> None:
        text = self.prompt.text().strip()
        if not text:
            return
        self.history.append(f"> {text}")
        self.prompt.clear()
        self.progress.setVisible(True)
        try:
            if self.plugin:
                reply = self.plugin.send_prompt(text)
                if reply:
                    self.history.append(reply)
        finally:
            self.progress.setVisible(False)
