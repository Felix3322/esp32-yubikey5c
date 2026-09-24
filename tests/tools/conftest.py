"""Offline unit tests of the host tools (tools/librefido): no emulator, no
PC/SC daemon; devices are simulated.

    PYTHONPATH=tools/librefido python -m pytest -q tests/tools
"""

import os
import sys

TOOLS = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                     "tools", "librefido")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)
