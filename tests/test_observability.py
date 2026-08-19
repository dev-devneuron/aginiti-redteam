import logging

from aginiti.core.observability import get_logger


def test_get_logger_namespaces_under_aginiti():
    logger = get_logger("my_module")
    assert logger.name == "aginiti.my_module"


def test_get_logger_does_not_double_prefix_an_already_namespaced_name():
    assert get_logger("aginiti.my_module").name == "aginiti.my_module"
    assert get_logger("aginiti").name == "aginiti"


def test_root_aginiti_logger_has_a_null_handler_and_no_output_by_default():
    # The library must never emit anything on its own (no basicConfig, no
    # StreamHandler attached at import time) -- only a NullHandler, so a
    # host application's own logging config is never overridden.
    root = logging.getLogger("aginiti")
    assert any(isinstance(h, logging.NullHandler) for h in root.handlers)
    assert not any(isinstance(h, logging.StreamHandler) for h in root.handlers)


def test_logger_output_is_capturable_once_a_handler_is_attached(caplog):
    # Proves this is genuinely functional logging, not just a namespacing
    # exercise -- exactly the "attach your own handler" pattern this
    # module's own docstring documents for a deploying application.
    logger = get_logger("test_capture_check")
    with caplog.at_level(logging.WARNING, logger="aginiti.test_capture_check"):
        logger.warning("a real warning message")
    assert "a real warning message" in caplog.text
