"""aginiti-redteam: red-teaming library for enterprise agentic AI systems.

``__version__`` is resolved from installed package metadata (which itself
comes from ``pyproject.toml``'s ``version`` field) so there is a single
source of truth — no second version string to fall out of sync when a
release is cut. Falls back to a static placeholder only when the package
is being imported from source without having been installed at all
(e.g. a source checkout added to ``sys.path`` directly, bypassing
``pip install -e .``).
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("aginiti-redteam")
except PackageNotFoundError:
    __version__ = "0.0.0.dev0"
