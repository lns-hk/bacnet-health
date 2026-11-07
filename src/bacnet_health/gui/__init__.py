"""Desktop GUI (PySide6, the ``bacnet-health[gui]`` extra). Entry point: :func:`bacnet_health.gui.app.main`.

The GUI holds no BACnet logic: active work goes through :mod:`bacnet_health.runner`, passive analysis through
:func:`bacnet_health.analysis.analyze.analyze_file`, and reports through :mod:`bacnet_health.report`.
"""
