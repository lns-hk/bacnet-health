"""The Windows GUI has no console: no helper program may be started in a way that flashes a window."""

from __future__ import annotations

import ast
import pathlib
import subprocess

import bacnet_health
from bacnet_health import _proc

SRC = pathlib.Path(bacnet_health.__file__).parent
STARTERS = {"run", "Popen", "call", "check_call", "check_output"}


def test_every_subprocess_call_hides_its_window():
    bad = []
    for path in SRC.rglob("*.py"):
        if path.name == "_proc.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"
                    and node.func.attr in STARTERS
                    and not any(k.arg == "creationflags" for k in node.keywords)):
                bad.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert not bad, f"use bacnet_health._proc.run_hidden: {bad}"


def test_run_hidden_sets_no_window_on_windows(monkeypatch):
    seen = {}
    monkeypatch.setattr(_proc.sys, "platform", "win32")
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: seen.update(kw, cmd=cmd))
    _proc.run_hidden(["w32tm", "/query", "/source"], capture_output=True, text=True)
    assert seen["creationflags"] & _proc.CREATE_NO_WINDOW
    assert seen["stdin"] == subprocess.DEVNULL
    assert seen["capture_output"] is True and seen["cmd"] == ["w32tm", "/query", "/source"]


def test_run_hidden_adds_no_flags_elsewhere(monkeypatch):
    seen = {}
    monkeypatch.setattr(_proc.sys, "platform", "darwin")
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: seen.update(kw))
    _proc.run_hidden(["true"])
    assert "creationflags" not in seen
