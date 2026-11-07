"""PyInstaller entry point of bacnet-health.exe (windowed GUI)."""

from bacnet_health.gui.app import main

if __name__ == "__main__":
    raise SystemExit(main())
