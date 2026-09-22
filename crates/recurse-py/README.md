# recurse-py

Python bindings for `recurse_static::engine::Engine` — the `idalib`
equivalent for Recurse. Open a binary, run every analysis op
(`functions`/`disasm`/`graph`/`lift`/`decompile`/`xrefs`/`strings`/`imports`/`info`)
directly from Python, and get back native `dict`/`list`/`str`/`int` — no IDA
seat, no license, and (for the `native` backend) no external tool at all.

```python
import recurse_py

eng = recurse_py.Engine("/path/to/binary")   # backend="native" (default) or "r2"
eng.analyze()

for f in eng.functions(limit=20)["items"]:
    print(hex(f["addr"]), f["name"])

addr = eng.resolve("main") or eng.functions(limit=1)["items"][0]["addr"]
print(eng.decompile(addr)["code"])          # C-like pseudocode (see docs/vtil-lift.md)
print(eng.lift(addr)["vtil"])               # VTIL-style de-obfuscated IL text
```

One class (`Engine`), one generic method (`call(op, **kwargs)`, the exact
same op vocabulary `recurse-agent`'s tool runtime and `recurse-mcp` both
use), plus convenience wrappers over it
(`functions`/`disasm`/`graph`/`lift`/`decompile`/`xrefs`/`strings`/`imports`/`info`/`raw`/`resolve`).
Every op returns the same compact-JSON envelope shape those other two
surfaces see, converted to native Python objects — never a JSON string you
parse yourself.

## Build

Two ways to get `import recurse_py` working, same result:

**Plain `cargo build`** (fastest for local iteration; what
`tests/conftest.py` does automatically):

```bash
cargo build -p recurse-py
# then either run pytest (conftest.py stages the extension itself), or by hand:
cp target/debug/recurse_py.dll target/debug/recurse_py.pyd   # Windows
# cp target/debug/librecurse_py.so target/debug/recurse_py.so     # Linux
# cp target/debug/librecurse_py.dylib target/debug/recurse_py.so # macOS
PYTHONPATH=target/debug python -c "import recurse_py; print(recurse_py.__version__)"
```

**[maturin](https://www.maturin.rs/)** (real wheel, what you'd actually
`pip install`):

```bash
pip install maturin
cd crates/recurse-py
maturin develop --release   # installs into the active virtualenv
# or: maturin build --release  ->  target/wheels/recurse_py-*.whl
```

Built as an `abi3-py38` extension: one compiled wheel per platform works
across Python 3.8+ without a rebuild per interpreter minor version.

## Test

```bash
cargo build -p recurse-py
pip install pytest
pytest crates/recurse-py/tests
```

Every test opens `sys.executable` (the interpreter running the test) as the
target binary, so the suite needs no fixture binary of its own and runs
identically on any platform's own Python install.
