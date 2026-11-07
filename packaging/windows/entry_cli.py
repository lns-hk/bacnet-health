"""PyInstaller entry point of bacnet-health-cli.exe (console)."""

from bacnet_health.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
