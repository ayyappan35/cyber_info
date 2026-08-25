from common.config import Settings


def test_cors_origins_list_default_includes_local_dev_and_deployed_frontend():
    origins = Settings().cors_origins_list()
    assert "http://localhost:5173" in origins
    assert "https://cyber-info-2.onrender.com" in origins


def test_cors_origins_list_strips_whitespace_and_trailing_slash():
    settings = Settings(cors_allowed_origins=" https://example.com/ , http://localhost:5173 ")
    assert settings.cors_origins_list() == ["https://example.com", "http://localhost:5173"]


def test_cors_origins_list_ignores_empty_entries():
    settings = Settings(cors_allowed_origins="https://example.com,,http://localhost:5173,")
    assert settings.cors_origins_list() == ["https://example.com", "http://localhost:5173"]
