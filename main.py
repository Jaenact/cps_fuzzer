#!/usr/bin/env python3
"""
ipTIME Firmware Fuzzer - Main Entry Point
"""

import sys
from pathlib import Path

# 프로젝트 루트 추가
sys.path.insert(0, str(Path(__file__).parent))

from core.controller import main


if __name__ == '__main__':
    main()
