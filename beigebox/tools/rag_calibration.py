"""
RAG Poisoning Detector Calibration Tool.

DEPRECATED 2026-05-04: This tool was built against ChromaDB, which has been
removed from BeigeBox in favor of PostgreSQL + pgvector. The
`PostgresBackend` does not (yet) expose a "scan all embeddings" API
equivalent to `chromadb.Collection.get(...)`, so the corpus-walk that this
script depended on no longer has a clean implementation.

If you need to recalibrate the RAG poisoning detector against a postgres
corpus, run the SQL directly:

    SELECT embedding FROM embeddings ORDER BY random() LIMIT 1000;

then feed those vectors into `RAGPoisoningDetector.update_baseline()` from
a one-off script. The tool below is preserved as a stub so the import path
keeps resolving for any external caller — invoking it exits with an error
explaining the deprecation.
"""

import argparse
import logging
import sys

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


def main() -> None:
    """Calibration CLI entry point — now a deprecation stub."""
    parser = argparse.ArgumentParser(
        description=(
            "DEPRECATED — this tool only supported ChromaDB, which was removed "
            "from BeigeBox on 2026-05-04. See module docstring for the migration "
            "path against PostgreSQL + pgvector."
        )
    )
    parser.add_argument("--chroma-path", required=False, help="(unused; deprecated)")
    parser.add_argument("--output", default="rag_calibration_stats.json")
    parser.add_argument("--max-samples", type=int, default=1000)
    parser.parse_args()

    logger.error(
        "rag_calibration is deprecated: ChromaDB was removed on 2026-05-04. "
        "Calibrate against the postgres corpus directly — see the module "
        "docstring for the SQL recipe."
    )
    sys.exit(2)


if __name__ == "__main__":
    main()
