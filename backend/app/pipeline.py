from .schemas import ScanResponse
from .stages import static_analysis, llm_discovery, llm_reasoning, ml_classifier, consistency, integration, fix_engine

STAGES = [static_analysis, llm_discovery, llm_reasoning, ml_classifier, consistency, integration, fix_engine]
# The builder re-scans several times, so it skips the two expensive stages (rename test, fix engine).
FAST_STAGES = [static_analysis, llm_discovery, llm_reasoning, ml_classifier, integration]


def run_pipeline(files, notes=None, stages=None) -> ScanResponse:
    stages = stages or STAGES
    findings = []
    for stage in stages:
        findings = stage.run(files, findings)
    status = [f"{s.__name__.rsplit('.', 1)[-1]}: {s.STATUS}" for s in stages if getattr(s, "STATUS", "")]
    return ScanResponse(
        findings=[f for f in findings if not f.reason],
        dismissed=[f for f in findings if f.reason],
        notes=(notes or []) + [f"Scanned {len(files)} file(s)."] + status
              + ["Decision support, not proof: a rule scanner, an LLM and a baseline model can all be wrong."])
