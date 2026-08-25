"""Tests for backend/pipelines/rag_search.py's relevance filtering
(MIN_RELEVANCE_SCORE) - the embedding/reranker models themselves are
mocked out so these stay fast and deterministic, matching this project's
established pattern of not loading real ML models in unit tests."""
from pipelines import rag_search


class _FakeReranker:
    def __init__(self, scores):
        self._scores = scores

    def predict(self, pairs):
        return self._scores


def _patch(monkeypatch, results, scores):
    monkeypatch.setattr(rag_search, "get_vectorstore", lambda: object())
    monkeypatch.setattr(rag_search, "safe_similarity_search", lambda vs, q, k, category_filter=None: results)
    monkeypatch.setattr(rag_search, "_get_reranker", lambda: _FakeReranker(scores))


def test_irrelevant_results_all_filtered_out(monkeypatch):
    results = [("some resume text", {"source": "resume.pdf"}, 0.1),
               ("some other unrelated chunk", {"source": "notes.md"}, 0.2)]
    _patch(monkeypatch, results, scores=[-11.0, -10.5])  # both well below MIN_RELEVANCE_SCORE
    out = rag_search.search_knowledge("how to apply nativity certificate")
    assert out == []


def test_relevant_results_kept_irrelevant_dropped(monkeypatch):
    results = [
        ("credential stuffing runbook content", {"source": "runbook.md"}, 0.1),
        ("unrelated resume text", {"source": "resume.pdf"}, 0.2),
    ]
    _patch(monkeypatch, results, scores=[4.3, -11.2])
    out = rag_search.search_knowledge("how does this system detect credential stuffing")
    assert len(out) == 1
    assert out[0]["source"] == "runbook.md"


def test_top_k_still_applied_after_relevance_filter(monkeypatch):
    results = [(f"relevant chunk {i}", {"source": f"doc{i}.md"}, 0.1) for i in range(5)]
    _patch(monkeypatch, results, scores=[3.0, 2.0, 1.0, 0.5, 0.1])  # all above threshold
    out = rag_search.search_knowledge("a relevant query", top_k=2)
    assert len(out) == 2
    assert out[0]["source"] == "doc0.md"  # highest score first


def test_score_exactly_at_threshold_is_kept(monkeypatch):
    results = [("borderline content", {"source": "borderline.md"}, 0.1)]
    _patch(monkeypatch, results, scores=[rag_search.MIN_RELEVANCE_SCORE])
    out = rag_search.search_knowledge("borderline query")
    assert len(out) == 1


def test_no_vectorstore_results_returns_empty_without_calling_reranker(monkeypatch):
    monkeypatch.setattr(rag_search, "get_vectorstore", lambda: object())
    monkeypatch.setattr(rag_search, "safe_similarity_search", lambda vs, q, k, category_filter=None: [])

    def _fail_if_called():
        raise AssertionError("reranker should not be invoked when there are no candidates")
    monkeypatch.setattr(rag_search, "_get_reranker", _fail_if_called)

    assert rag_search.search_knowledge("anything") == []
