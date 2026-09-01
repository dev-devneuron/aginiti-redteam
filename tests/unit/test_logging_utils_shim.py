"""Verifies aginiti/core/logging_utils.py -- the backward-compatible
re-export shim left behind by the rename to aginiti.core.trial_logging --
actually re-exports the same objects, not copies."""
import aginiti.core.logging_utils as logging_utils_shim
import aginiti.core.trial_logging as trial_logging


def test_logging_utils_shim_reexports_same_objects():
    assert logging_utils_shim.campaign_result_to_dict is trial_logging.campaign_result_to_dict
    assert logging_utils_shim.new_run_id is trial_logging.new_run_id
    assert logging_utils_shim.run_dir is trial_logging.run_dir
    assert logging_utils_shim.save_trial is trial_logging.save_trial
    assert logging_utils_shim.save_json is trial_logging.save_json
    assert logging_utils_shim.load_json is trial_logging.load_json
