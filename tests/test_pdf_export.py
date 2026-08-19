import pytest

from aginiti.core.pdf_export import _find_browser


def test_finds_a_browser_on_this_machine():
    # Not mocked deliberately -- this is a real environment check (do we
    # have SOME Chromium-based browser to shell out to), not a unit test
    # of pure logic. Skips gracefully on a machine with neither installed.
    try:
        path = _find_browser()
    except RuntimeError:
        pytest.skip("no Chrome/Edge/Chromium installed on this machine")
    else:
        assert path
