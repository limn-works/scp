"""Tests for `_cargo_target_dir`, which the `kotlin_runner` fixture reads."""

from __future__ import annotations

import subprocess

import pytest

from . import conftest


def _forbid_cargo(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
    raise AssertionError("cargo ran although CARGO_TARGET_DIR was set")


def test_set_target_dir_is_read_without_running_cargo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(conftest.subprocess, "run", _forbid_cargo)
    monkeypatch.setenv("CARGO_TARGET_DIR", "/ci/workspace/target")
    assert conftest._cargo_target_dir() == conftest.Path("/ci/workspace/target")


def test_relative_target_dir_resolves_against_repo_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(conftest.subprocess, "run", _forbid_cargo)
    monkeypatch.setenv("CARGO_TARGET_DIR", "target")
    assert conftest._cargo_target_dir() == conftest._REPO_ROOT / "target"


@pytest.mark.parametrize("value", [None, ""])
def test_unset_or_empty_target_dir_asks_cargo(
    monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout='{"target_directory": "/shared"}')

    monkeypatch.setattr(conftest.subprocess, "run", fake_run)
    if value is None:
        monkeypatch.delenv("CARGO_TARGET_DIR", raising=False)
    else:
        monkeypatch.setenv("CARGO_TARGET_DIR", value)
    assert conftest._cargo_target_dir() == conftest.Path("/shared")
    assert calls == [["cargo", "metadata", "--format-version", "1", "--no-deps"]]
