"""One-time ingestion of knowledge/**/*.md runbooks into the cyber_defense_kb
Chroma collection, via the same training pipeline (ingest_chroma.py) that
the upload MCP tool uses - no separate ingestion logic here.

Files are grouped by their immediate parent folder name under knowledge/
(e.g. knowledge/mitre_attack/foo.md -> category="mitre_attack"), stamped
into each chunk's metadata so retrieval can be filtered by category."""
import argparse
import glob
import os
import shutil
import sys

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "backend", "pipelines"))

from ingest_chroma import ingest_files
from rag_search import DB_DIR

KNOWLEDGE_DIR = os.path.join(_PROJECT_ROOT, "knowledge")


def seed():
    paths = sorted(glob.glob(os.path.join(KNOWLEDGE_DIR, "**", "*.md"), recursive=True))
    by_category = {}
    for path in paths:
        category = os.path.basename(os.path.dirname(path))
        by_category.setdefault(category, []).append(path)

    total = 0
    for category, cat_paths in sorted(by_category.items()):
        # First-party curated runbooks, not user uploads - ingested directly,
        # never routed through security_gateway's file_security check (that
        # check exists for admin *uploads* specifically - see
        # skills/malicious_pdf/SKILL.md and backend/routers/upload_router.py).
        n = ingest_files(cat_paths, category=category, origin="seed")
        total += n

    print(f"Ingested {total} chunks from {len(paths)} runbooks across {len(by_category)} categories.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true",
                         help="Delete the existing kb_chroma_db/ directory before reseeding, "
                              "to avoid duplicate/uncategorized chunks left over from a prior "
                              "flat-layout ingestion (Chroma has no dedup on re-ingest).")
    args = parser.parse_args()

    if args.reset and os.path.isdir(DB_DIR):
        shutil.rmtree(DB_DIR)
        print(f"Removed existing {DB_DIR}")

    seed()
