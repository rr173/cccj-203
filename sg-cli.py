#!/usr/bin/env python3
"""Launcher: keeps the sg package importable regardless of CWD.

Run with -I so untrusted data directories can never inject modules
(python -I ignores PYTHONPATH, so we insert the absolute lib path here).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sg.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
