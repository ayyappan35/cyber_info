import os
import sys

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND_DIR = os.path.join(_PROJECT_ROOT, "backend")
for p in (_PROJECT_ROOT, _BACKEND_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

import pytest


@pytest.fixture
def temp_sqlite_path(tmp_path):
    return str(tmp_path / "test.db")
