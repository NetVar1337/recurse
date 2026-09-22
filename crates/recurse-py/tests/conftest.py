"""Makes ``import recurse_py`` work against a plain ``cargo build -p
recurse-py`` output, so ``pytest crates/recurse-py/tests`` needs nothing
beyond the Rust toolchain for local development.

For a real installable wheel, use maturin instead (see ../README.md):

    maturin develop --release
    pytest crates/recurse-py/tests

Either path lands on the same ``import recurse_py`` — this shim only saves
having maturin installed for a quick local test run.
"""

import pathlib
import platform
import shutil
import sys

_CRATE_ROOT = pathlib.Path(__file__).resolve().parents[1]
_TARGET = _CRATE_ROOT.parent.parent / "target" / "debug"


def _staged_extension() -> pathlib.Path | None:
    system = platform.system()
    if system == "Windows":
        src, dst = _TARGET / "recurse_py.dll", _TARGET / "recurse_py.pyd"
    elif system == "Darwin":
        src, dst = _TARGET / "librecurse_py.dylib", _TARGET / "recurse_py.so"
    else:
        src, dst = _TARGET / "librecurse_py.so", _TARGET / "recurse_py.so"

    if not src.exists():
        return None
    if not dst.exists() or src.stat().st_mtime > dst.stat().st_mtime:
        shutil.copyfile(src, dst)
    return _TARGET


staged = _staged_extension()
if staged is not None and str(staged) not in sys.path:
    sys.path.insert(0, str(staged))
