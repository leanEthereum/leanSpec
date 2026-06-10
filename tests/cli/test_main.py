"""Tests for the process entry point."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from lean_spec.cli import main


class TestMainEntry:
    """Smoke tests for the process entry point."""

    def test_help_exits_cleanly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The standard help flag exits the process with status zero."""
        monkeypatch.setattr(sys, "argv", ["leanspec", "--help"])
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 0

    def test_missing_genesis_file_exits_non_zero(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """A non-existent genesis path triggers a non-zero exit before reaching the run loop."""
        missing = tmp_path / "does-not-exist.yaml"
        monkeypatch.setattr(sys, "argv", ["leanspec", "--genesis", str(missing)])
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 1
