#!/usr/bin/env python3
"""GUI 대시보드 진입점"""
import sys
import os

# 프로젝트 루트를 Python 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.main import main

if __name__ == "__main__":
    main()
