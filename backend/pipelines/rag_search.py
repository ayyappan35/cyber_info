"""Lightweight retrieve+rerank search over the cyber-defense knowledge base.

Shared by ingest_chroma.py (training) and rag_graph_chroma.py (query) - both
live alongside this file in backend/pipelines/. Wrapped as MCP tools in
mcp_servers/threatintel_mcp.py and mcp_servers/training_mcp.py; nothing
outside those tool wrappers should import this module directly.
"""
import os

from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from sentence_transformers import CrossEncoder

# The knowledge/ subfolder names seed_knowledge.py stamps as each chunk's
# "category" metadata. Real, observed bug (2026-08-24): mcp_servers/
# threatintel_mcp.py's answer_question tool takes a free-text `category`
# argument with no enumeration in its own docstring (unlike
# search_knowledge_base's, which lists these) - the small local model
# invented a plausible-looking value ("ATC-Attack_Techniques") that matches
# nothing, and Chroma's metadata filter on a category that doesn't exist
# silently returns zero results rather than erroring - "I don't have that
# information" for a question the knowledge base actually could answer.
# search_knowledge() now ignores an unrecognized category instead of
# filtering to nothing on it - a bad guess should degrade to "search
# everything", not to "search nothing".
VALID_CATEGORIES = {"mitre_attack", "owasp_agentic", "security_policies",
                     "incident_response", "tool_policies"}

# Real, observed problem (2026-08-24): search_knowledge_base always returned
# top_k results regardless of actual relevance - Chroma's nearest-neighbor
# search returns SOMETHING even when nothing in the collection is actually
# related to the query, so a query like "how to apply nativity certificate"
# (nothing to do with this KB) still surfaced the least-irrelevant chunks it
# had, including an uploaded resume PDF - which then dragged that resume's
# PII into context for a completely unrelated question, triggering
# skills/rag/pii-exposure's routing (context_contains_pii alone) and biasing
# the Security LLM Discussion toward BLOCK on a question that had nothing to
# do with the PII at all. The real fix is retrieval precision, not more
# skill/floor logic on top of a bad retrieval: cross-encoder/
# ms-marco-MiniLM-L-6-v2's score is an unbounded relevance logit, and a
# calibration run against this project's own KB showed a wide, clean gap
# between genuinely relevant matches (scores from ~-1.4 up to ~4.3) and
# actually-irrelevant ones (below -9) - MIN_RELEVANCE_SCORE sits well
# inside that gap, so this only drops matches with nothing genuinely to do
# with the query, never a real (if imperfect) match.
MIN_RELEVANCE_SCORE = -2.0

# kb_chroma_db is project data, not code - keep it at the project root
# (three levels up from backend/pipelines/rag_search.py) regardless of where
# this module lives, so moving this file never orphans the ingested data.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_DIR = os.path.join(_PROJECT_ROOT, "kb_chroma_db")
COLLECTION_NAME = "cyber_defense_kb"

_embedding_model = None
_reranker = None


def _get_embedding_model():
    global _embedding_model
    if _embedding_model is None:
        _embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
    return _embedding_model


def _get_reranker():
    global _reranker
    if _reranker is None:
        _reranker = CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")
    return _reranker


def get_vectorstore():
    return Chroma(
        persist_directory=DB_DIR,
        collection_name=COLLECTION_NAME,
        embedding_function=_get_embedding_model(),
    )


def safe_similarity_search(vectorstore, query: str, k: int, category_filter: str | None = None):
    """Queries the raw chromadb collection directly instead of going through
    langchain_community.Chroma.similarity_search_with_score(), which
    crashes (pydantic ValidationError on Document(page_content=None)) if
    Chroma returns a stale/orphaned entry - a real, observed failure mode
    after mcp_servers/rag_defence_mcp.py's record_threat_assessment REJECT
    action deletes a chunk (vectorstore.delete(where=...)): Chroma's HNSW
    index can briefly retain a reference whose backing document text is
    already gone. Returns a list of (content, metadata, distance) tuples,
    silently skipping any entry with no content instead of crashing the
    whole query - one corrupted/deleted entry must not take down retrieval
    for every other, valid result."""
    embedding = _get_embedding_model().embed_query(query)
    where = {"category": category_filter} if category_filter else None
    raw = vectorstore._collection.query(query_embeddings=[embedding], n_results=k, where=where)
    documents = (raw.get("documents") or [[]])[0]
    metadatas = (raw.get("metadatas") or [[]])[0]
    distances = (raw.get("distances") or [[]])[0]
    return [
        (content, meta or {}, dist)
        for content, meta, dist in zip(documents, metadatas, distances)
        if content is not None
    ]


def search_knowledge(query: str, top_k: int = 3, category_filter: str | None = None) -> list[dict]:
    """Retrieve then rerank runbook/threat-intel chunks relevant to `query`.
    If category_filter is given, only chunks tagged with that knowledge/
    subfolder category (e.g. "mitre_attack") are considered. An unrecognized
    category (not in VALID_CATEGORIES - a real observed failure mode: the
    calling LLM invents one) is ignored rather than applied, so a bad guess
    degrades to "search everything" instead of "search nothing". There is no
    retrieval-time trust filter here - security_gateway/gateway.py's
    file_security check runs BEFORE a document is ever ingested (see
    backend/pipelines/ingest_chroma.py), so everything in this collection
    was already ALLOWed; rag_security's live per-query check
    (rag_graph_chroma.py) is the defense-in-depth layer against anything
    that check missed."""
    if category_filter and category_filter not in VALID_CATEGORIES:
        category_filter = None
    vectorstore = get_vectorstore()
    results = safe_similarity_search(vectorstore, query, k=10, category_filter=category_filter)

    if not results:
        return []

    pairs = [[query, content] for content, _meta, _dist in results]
    scores = _get_reranker().predict(pairs)

    reranked = sorted(
        (
            {
                "content": content,
                "source": meta.get("source", ""),
                "document_id": meta.get("document_id"),
                "chunk_id": meta.get("chunk_id"),
                "rerank_score": float(score),
            }
            for (content, meta, _dist), score in zip(results, scores)
        ),
        key=lambda x: x["rerank_score"],
        reverse=True,
    )

    # Below MIN_RELEVANCE_SCORE means "nothing in the collection is actually
    # about this query" - returning those anyway is worse than returning
    # nothing: it drags unrelated (and possibly sensitive) content into
    # context for a question that has nothing to do with it. See
    # MIN_RELEVANCE_SCORE's comment above for how this threshold was picked.
    relevant = [r for r in reranked if r["rerank_score"] >= MIN_RELEVANCE_SCORE]
    return relevant[:top_k]
