"""Tests for the ``recurse_py`` extension module.

Build first (``conftest.py`` stages whichever of these already exists onto
``sys.path``, so either is enough):

    cargo build -p recurse-py          # fastest for local iteration
    maturin develop --release          # real wheel-equivalent install

Every test opens ``sys.executable`` (the interpreter running the test) as
the target binary — always present, always a real PE/ELF/Mach-O, so the
suite needs no fixture binary of its own.
"""

import sys

import pytest

import recurse_py


@pytest.fixture()
def engine() -> "recurse_py.Engine":
    eng = recurse_py.Engine(sys.executable)
    eng.analyze()
    return eng


def test_backend_defaults_to_native() -> None:
    eng = recurse_py.Engine(sys.executable)
    assert eng.backend() == "native"


def test_unknown_backend_raises() -> None:
    with pytest.raises(RuntimeError):
        recurse_py.Engine(sys.executable, backend="ghidra")


def test_functions_returns_a_populated_envelope(engine: "recurse_py.Engine") -> None:
    out = engine.functions(limit=3)
    assert out["op"] == "functions"
    assert out["count"] > 0
    assert 0 < len(out["items"]) <= 3
    assert isinstance(out["items"][0]["addr"], int)
    assert isinstance(out["items"][0]["name"], str)


def test_lift_and_decompile_round_trip(engine: "recurse_py.Engine") -> None:
    addr = engine.functions(limit=1)["items"][0]["addr"]

    lifted = engine.lift(addr)
    assert "vtil" in lifted
    assert "optimized" in lifted
    assert isinstance(lifted["optimized"], dict)

    dec = engine.decompile(addr)
    assert dec["code"]
    assert "void " in dec["code"]


def test_addr_accepts_int_or_symbol_name(engine: "recurse_py.Engine") -> None:
    first = engine.functions(limit=1)["items"][0]
    by_int = engine.disasm(first["addr"])
    by_name = engine.disasm(first["name"])
    assert by_int["addr"] == by_name["addr"]


def test_call_matches_the_named_convenience_method(engine: "recurse_py.Engine") -> None:
    via_method = engine.functions(limit=2)
    via_call = engine.call("functions", limit=2)
    assert via_method["count"] == via_call["count"]
    assert via_method["items"] == via_call["items"]


def test_resolve_unknown_symbol_is_none(engine: "recurse_py.Engine") -> None:
    assert engine.resolve("this_symbol_does_not_exist_anywhere_at_all") is None


def test_strings_and_imports_return_json_native_types(engine: "recurse_py.Engine") -> None:
    strings = engine.strings(limit=5)
    assert isinstance(strings["items"], list)

    imports = engine.imports(limit=5)
    assert isinstance(imports["items"], list)


def test_repr_names_the_path_and_backend() -> None:
    eng = recurse_py.Engine(sys.executable)
    text = repr(eng)
    assert "Engine(" in text
    assert "backend=\"native\"" in text
