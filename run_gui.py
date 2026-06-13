#!/usr/bin/env python3
"""GUI 대시보드 진입점"""
import sys
import os
import argparse

# 프로젝트 루트를 Python 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.main import main

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="이상탐지 MLOps 대시보드")
    parser.add_argument("--present", action="store_true",
                        help="발표 모드로 시작 (스테이지 뷰 + 전체화면, F5 토글)")
    args = parser.parse_args()
    main(present=args.present)
