"""pytest 루트 설정 — tests/에서 상위 모듈(guard, rules…)을 import할 수 있게 경로 보정."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
