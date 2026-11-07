"""Packaging spike: console CLI exe living next to the GUI exe."""
import json
import sys

import bacnet_health


def main() -> int:
    print(f"bacnet-health {bacnet_health.__version__} (packaging test)")
    if "--interfaces" in sys.argv:
        from bacnet_health.active import _win

        for d in _win.list_interfaces_windows():
            print(json.dumps(d))
    return 0


if __name__ == "__main__":
    sys.exit(main())
