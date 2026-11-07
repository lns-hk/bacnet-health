"""PyInstaller runtime hook (GUI exe only): keep the Qt window light when Windows uses dark mode for apps.

The GUI's stylesheet is a light theme, but Qt 6 on Windows follows the "dark app mode" setting for every widget
part the stylesheet does not colour (menu bar, table headers, the finding-details text panel), which made those
parts black or unreadable. ``darkmode=0`` tells the Windows platform plugin to ignore the setting. A value the user
set explicitly (e.g. QT_QPA_PLATFORM=offscreen) is kept.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "windows:darkmode=0")
