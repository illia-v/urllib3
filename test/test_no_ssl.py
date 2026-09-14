"""
Test what happens if Python was built without SSL

* Everything that does not involve HTTPS should still work
* HTTPS requests must fail with an error that points at the ssl module
"""

from __future__ import annotations

import sys
from test import ModuleStash
from unittest.mock import patch

import pytest


@patch.dict(sys.modules, {"ssl": None, "_ssl": None})
class TestImportWithoutSSL:
    def test_cannot_import_ssl(self) -> None:
        with pytest.raises(ImportError):
            import ssl  # noqa: F401

    def test_import_urllib3(self) -> None:
        # Import urllib3 again while SSL is blocked instead of reusing
        # cached modules.
        module_stash = ModuleStash("urllib3")
        module_stash.stash()
        try:
            from urllib3.connection import DummyConnection, HTTPSConnection

            assert HTTPSConnection is DummyConnection  # type: ignore[comparison-overlap]
        finally:
            module_stash.pop()
