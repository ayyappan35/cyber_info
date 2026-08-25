"""One-time ingestion of knowledge/cyber_defence/*.md into the SEPARATE
security_threat_knowledge Chroma collection (backend/pipelines/threat_knowledge.py)
- deliberately not the same collection seed_knowledge.py populates.
"""
import glob
import os
import sys

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "backend", "pipelines"))

from threat_knowledge import ingest_threat_knowledge_file, THREAT_KNOWLEDGE_COLLECTION

KNOWLEDGE_DIR = os.path.join(_PROJECT_ROOT, "knowledge", "cyber_defence")


def seed():
    paths = sorted(glob.glob(os.path.join(KNOWLEDGE_DIR, "*.md")))
    total = 0
    for path in paths:
        n = ingest_threat_knowledge_file(path)
        print(f"  {path}: {n} chunks")
        total += n
    print(f"Ingested {total} chunks from {len(paths)} files into '{THREAT_KNOWLEDGE_COLLECTION}'.")


if __name__ == "__main__":
    seed()
