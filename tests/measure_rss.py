#!/usr/bin/env python3
"""Run a gate subcommand in-process and report peak RSS (kilobytes on Linux)."""
import resource
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sg.cli import main

rc = main(sys.argv[1:])
peak_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
sys.stderr.write(f"PEAK_RSS_KB={peak_kb}\n")
sys.exit(rc)
