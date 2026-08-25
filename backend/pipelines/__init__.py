"""Modules in this package (rag_search.py, ingest_chroma.py,
rag_graph_chroma.py, threat_knowledge.py) import each other with bare
names (`from rag_search import ...`), not package-relative imports, so
this directory must be on sys.path directly - not just importable as the
`backend.pipelines` package - for those cross-imports to resolve.
Importing this package (`from pipelines.x import y` or
`from backend.pipelines.x import y`) makes sure of that as a side effect,
so callers never need to remember to do it themselves.
"""
import os
import sys

_PIPELINES_DIR = os.path.dirname(os.path.abspath(__file__))
if _PIPELINES_DIR not in sys.path:
    sys.path.insert(0, _PIPELINES_DIR)
