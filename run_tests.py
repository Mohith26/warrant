"""Tiny test runner so the suite works with or without pytest installed.

    python run_tests.py
"""

import importlib
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main():
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "tests"))

    modules = sorted(p.stem for p in (ROOT / "tests").glob("test_*.py"))
    passed, failed = 0, []

    for name in modules:
        mod = importlib.import_module(name)
        for attr in sorted(dir(mod)):
            if not attr.startswith("test_"):
                continue
            fn = getattr(mod, attr)
            if not callable(fn):
                continue
            try:
                fn()
                passed += 1
                print(f"  ok   {name}.{attr}")
            except Exception:
                failed.append(f"{name}.{attr}")
                print(f"  FAIL {name}.{attr}")
                traceback.print_exc()

    print(f"\n{passed} passed, {len(failed)} failed")
    if failed:
        print("failures: " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
