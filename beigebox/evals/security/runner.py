"""
Reproducible TPR/FPR runner for BeigeBox security detectors.

Each suite loads a YAML corpus of labeled examples (label ∈ {malicious, benign}),
runs the relevant detector on each, and tallies TP/FP/TN/FN. Metrics are printed
as a table; ``--json`` returns a machine-readable result so this can be wired
into CI and a dashboard.

Suite contract:
  - Corpus YAML: ``corpora/<suite>.yaml``
  - Each row: ``{ id, label, text }`` (or detector-specific fields).
  - Suite implements ``run(rows)`` returning a list of (row_id, label, predicted_malicious).

Suites today:
  - injection            → enhanced_injection_guard
  - rag_poisoning        → rag_poisoning_detector (synthetic embeddings)
  - extraction           → extraction_detector
  - output_redaction     → output_redactor

Each suite is best-effort: missing detectors (e.g. semantic embedding model
unavailable) are reported as "skipped" rather than failing the run.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

CORPUS_DIR = Path(__file__).parent / "corpora"


@dataclass
class SuiteResult:
    name: str
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    skipped_reason: str | None = None
    duration_s: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def tpr(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def fpr(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.tpr
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "total": self.total,
            "tpr": round(self.tpr, 4),
            "fpr": round(self.fpr, 4),
            "precision": round(self.precision, 4),
            "f1": round(self.f1, 4),
            "duration_s": round(self.duration_s, 3),
            "skipped_reason": self.skipped_reason,
            "errors": self.errors,
        }


def _load_yaml(path: Path) -> list[dict]:
    """Load YAML corpus with JIT-generated test secrets (no real API keys in git)."""
    try:
        # Use corpus loader which substitutes ${SECRET:type} placeholders
        from beigebox.evals.security.corpus_loader import load_corpus
        return load_corpus(path)
    except (ModuleNotFoundError, ImportError):
        # Fallback: load YAML directly (secrets will be unsubstituted ${SECRET:...})
        try:
            import yaml  # type: ignore
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            return data.get("rows", []) if isinstance(data, dict) else (data or [])
        except ModuleNotFoundError:
            # Final fallback: JSON-Lines corpus
            jsonl = path.with_suffix(".jsonl")
            if jsonl.exists():
                rows = []
                with open(jsonl, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            rows.append(json.loads(line))
                return rows
            raise


def _tally(rows: list[dict], predict: Callable[[dict], bool]) -> SuiteResult:
    """Run *predict* across *rows* and tally TP/FP/TN/FN."""
    res = SuiteResult(name="(unset)")
    t0 = time.monotonic()
    for row in rows:
        label = row.get("label")
        try:
            pred = bool(predict(row))
        except Exception as exc:  # noqa: BLE001
            res.errors.append(f"{row.get('id', '?')}: {type(exc).__name__}: {exc}")
            continue
        if label == "malicious":
            if pred: res.tp += 1
            else:    res.fn += 1
        elif label == "benign":
            if pred: res.fp += 1
            else:    res.tn += 1
        else:
            res.errors.append(f"{row.get('id', '?')}: unknown label {label!r}")
    res.duration_s = time.monotonic() - t0
    return res


# ── Suites ─────────────────────────────────────────────────────────────────

def suite_injection() -> SuiteResult:
    name = "injection"
    rows = _load_yaml(CORPUS_DIR / "injection.yaml")
    try:
        from beigebox.security.enhanced_injection_guard import PatternLibrary
    except Exception as exc:  # noqa: BLE001
        return SuiteResult(name=name, skipped_reason=f"import failed: {exc}")

    def pred(row: dict) -> bool:
        # Pattern-only path. The semantic layer needs an embedding model and
        # is host-dependent; CI runs the patterns alone for reproducibility.
        return bool(PatternLibrary.scan(row["text"]))

    out = _tally(rows, pred)
    out.name = name
    return out


def suite_rag_poisoning() -> SuiteResult:
    name = "rag_poisoning"
    try:
        import numpy as np  # noqa: F401
        from beigebox.security.rag_poisoning_detector import RAGPoisoningDetector
    except Exception as exc:  # noqa: BLE001
        return SuiteResult(name=name, skipped_reason=f"import failed: {exc}")

    import numpy as np
    rng = np.random.default_rng(42)
    detector = RAGPoisoningDetector(sensitivity=0.95, baseline_window=200)

    # Build benign baseline: 200 unit-norm-ish embeddings
    benign = []
    for i in range(200):
        v = rng.standard_normal(384)
        v /= np.linalg.norm(v)
        benign.append({"id": f"benign_{i}", "label": "benign", "vec": v})
        detector.update_baseline(v)

    # Malicious: inflated-norm or zero-norm vectors
    malicious = []
    for i in range(50):
        scale = float(rng.choice([0.001, 50.0, 200.0]))
        v = rng.standard_normal(384) * scale
        malicious.append({"id": f"mal_{i}", "label": "malicious", "vec": v})

    rows = malicious + benign[:50]  # equal size for symmetric metrics

    def pred(row: dict) -> bool:
        is_poisoned, _conf, _reason = detector.is_poisoned(row["vec"])
        return is_poisoned

    out = _tally(rows, pred)
    out.name = name
    return out


def suite_extraction() -> SuiteResult:
    name = "extraction"
    try:
        from beigebox.security.extraction_detector import ExtractionDetector
    except Exception as exc:  # noqa: BLE001
        return SuiteResult(name=name, skipped_reason=f"import failed: {exc}")
    rows = _load_yaml(CORPUS_DIR / "extraction.yaml")
    detector = ExtractionDetector()

    def pred(row: dict) -> bool:
        sid = row.get("session_id", row["id"])
        # Replay warm-up turns to establish a baseline; judge the final probe.
        turns = row.get("turns", [{"text": row["text"]}])
        result = None
        for t in turns:
            result = detector.check_request(
                session_id=sid, user_id="eval",
                prompt=t["text"], model="eval-model",
            )
        if result is None:
            return False
        return getattr(result, "score", 0.0) >= 0.5

    out = _tally(rows, pred)
    out.name = name
    return out


def suite_output_redaction() -> SuiteResult:
    name = "output_redaction"
    try:
        from beigebox.security.output_redactor import OutputRedactor
    except Exception as exc:  # noqa: BLE001
        return SuiteResult(name=name, skipped_reason=f"import failed: {exc}")
    rows = _load_yaml(CORPUS_DIR / "output_redaction.yaml")
    redactor = OutputRedactor({"security": {"output_redaction": {"enabled": True}}})

    def pred(row: dict) -> bool:
        return redactor.redact(row["text"]).redacted

    out = _tally(rows, pred)
    out.name = name
    return out


SUITES: dict[str, Callable[[], SuiteResult]] = {
    "injection": suite_injection,
    "rag_poisoning": suite_rag_poisoning,
    "extraction": suite_extraction,
    "output_redaction": suite_output_redaction,
}


# ── Driver ─────────────────────────────────────────────────────────────────

# Below this corpus size, we publish numbers but warn that they're indicative,
# not statistically meaningful. Bumping the corpora past the threshold is the
# right way to silence the banner — not lowering the threshold.
PRELIMINARY_THRESHOLD = 200


def _print_table(results: list[SuiteResult]) -> None:
    preliminary = [r for r in results if not r.skipped_reason and r.total < PRELIMINARY_THRESHOLD]
    if preliminary:
        print()
        print("  ⚠  PRELIMINARY: corpus size below the publishability threshold")
        print(f"     ({PRELIMINARY_THRESHOLD} examples per suite). Numbers below are")
        print("     a regression floor, NOT a TPR/FPR claim suitable for a release note.")
        print(f"     Suites currently small: " + ", ".join(
            f"{r.name}({r.total})" for r in preliminary
        ))
    cols = ("Suite", "TP", "FP", "TN", "FN", "TPR", "FPR", "F1", "ms")
    rows = []
    for r in results:
        if r.skipped_reason:
            rows.append((r.name, "—", "—", "—", "—", "—", "—", "—", "skipped"))
            continue
        rows.append((
            r.name,
            str(r.tp), str(r.fp), str(r.tn), str(r.fn),
            f"{r.tpr:.3f}", f"{r.fpr:.3f}", f"{r.f1:.3f}",
            f"{r.duration_s * 1000:.0f}",
        ))
    widths = [max(len(c), max((len(r[i]) for r in rows), default=0)) for i, c in enumerate(cols)]
    line = "  ".join(c.ljust(widths[i]) for i, c in enumerate(cols))
    print()
    print(line)
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(row[i].ljust(widths[i]) for i in range(len(cols))))
    print()
    for r in results:
        if r.skipped_reason:
            print(f"  ! {r.name}: skipped — {r.skipped_reason}")
        if r.errors:
            print(f"  ! {r.name}: {len(r.errors)} error(s); first: {r.errors[0]}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="BeigeBox security eval harness")
    p.add_argument("--suite", choices=list(SUITES) + ["all"], default="all")
    p.add_argument("--json", action="store_true", help="JSON output for CI")
    args = p.parse_args(argv)

    targets = list(SUITES.values()) if args.suite == "all" else [SUITES[args.suite]]
    results = [fn() for fn in targets]

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        _print_table(results)

    return 0


if __name__ == "__main__":
    sys.exit(main())
