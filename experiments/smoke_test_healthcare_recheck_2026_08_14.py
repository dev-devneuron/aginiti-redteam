"""Re-check of the 2 operators that hit healthcare_agent's now-fixed
embedding-dimension-mismatch bug during the earlier sweep. 2026-08-14."""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("healthcare_recheck")

sys.path.insert(0, str(Path(__file__).parent.parent))

from aginiti.adapter.observation_adapter import ObservationAdapter  # noqa: E402
from aginiti.adapters.healthcare_agent_adapter import HealthcareAgentAdapter  # noqa: E402
from aginiti.adapters.scaled_evals_ground_truth import VerbatimDisclosureIndex  # noqa: E402
from aginiti.graph.ssg import SecurityStateGraph  # noqa: E402
from aginiti.operators.healthcare_agent_definitions import build_healthcare_agent_library  # noqa: E402
from aginiti.operators.library import OperatorLibrary  # noqa: E402

_DATASETS = Path(__file__).parent.parent / "benchmarks" / "scaled_evals" / "datasets"


def main() -> None:
    hc_index = VerbatimDisclosureIndex.from_json_files(_DATASETS / "healthcaremagic_1k.json")
    agent = HealthcareAgentAdapter(disclosure_index=hc_index)
    library = OperatorLibrary(build_healthcare_agent_library(hc_index))
    ssg = SecurityStateGraph()
    adapter = ObservationAdapter()

    results = {}
    for op_id in ("access_control_layer_probe_contrast_check", "session_isolation_probe_concurrent_other_user"):
        op = library.get(op_id)
        r = adapter.execute(op, ssg, agent, seed=42)
        results[op_id] = {"overall_success": r.overall_success, "preview": (r.raw_signal or "")[:300]}
        logger.info("RECHECK [%s]: %s", op_id, results[op_id])

    Path("runs_healthcare_recheck_2026_08_14.json").write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
