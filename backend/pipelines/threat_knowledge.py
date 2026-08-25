"""A separate security-threat knowledge base, deliberately NOT the same
Chroma collection as the trusted business knowledge base (rag_search.py's
`cyber_defense_kb`). Same underlying Chroma persistence directory
(kb_chroma_db/) but a distinct collection - Chroma scopes similarity
search to one collection at a time, so this is a logically separate store
with no risk of a threat-knowledge reference doc surfacing as an answer to
a SOC analyst's ordinary question, or vice versa.

Seeded from knowledge/cyber_defence/*.md (seed_threat_knowledge.py) -
reference material for agents/rag_defence.py's per-chunk scan to ground its
reasoning in (search_threat_knowledge, exposed as an MCP tool in
mcp_servers/rag_defence_mcp.py).
"""
from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

from rag_search import DB_DIR, _get_embedding_model, _get_reranker

THREAT_KNOWLEDGE_COLLECTION = "security_threat_knowledge"


def get_threat_knowledge_vectorstore():
    return Chroma(
        persist_directory=DB_DIR,
        collection_name=THREAT_KNOWLEDGE_COLLECTION,
        embedding_function=_get_embedding_model(),
    )


def search_threat_knowledge(query: str, top_k: int = 3) -> list:
    vectorstore = get_threat_knowledge_vectorstore()
    results = vectorstore.similarity_search_with_score(query=query, k=10)
    if not results:
        return []

    pairs = [[query, doc.page_content] for doc, _score in results]
    scores = _get_reranker().predict(pairs)

    reranked = sorted(
        (
            {"content": doc.page_content, "source": doc.metadata.get("source", ""),
             "rerank_score": float(score)}
            for (doc, _vscore), score in zip(results, scores)
        ),
        key=lambda x: x["rerank_score"],
        reverse=True,
    )
    return reranked[:top_k]


def ingest_threat_knowledge_file(path: str) -> int:
    """Ingest one markdown reference file by path into the threat-knowledge
    collection. No trust-gating here (unlike ingest_chroma.py) - this
    collection only ever holds first-party-authored security reference
    material, never user/attacker-supplied content, so there's nothing to
    scan before trusting it."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    import os
    doc = Document(page_content=text, metadata={"source": os.path.basename(path)})
    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=150)
    chunks = splitter.split_documents([doc])
    get_threat_knowledge_vectorstore().add_documents(chunks)
    return len(chunks)
