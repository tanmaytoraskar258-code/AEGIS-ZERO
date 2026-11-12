from src.ingestion.cve_matcher import CVEMatcher


def test_cve_matcher_uses_osv_query_endpoint():
    assert CVEMatcher().osv_api_url == "https://api.osv.dev/v1/query"
    assert CVEMatcher("https://osv.dev").osv_api_url == "https://api.osv.dev/v1/query"
    assert CVEMatcher("https://api.osv.dev").osv_api_url == "https://api.osv.dev/v1/query"
    assert (
        CVEMatcher("https://api.osv.dev/v1/query/").osv_api_url
        == "https://api.osv.dev/v1/query"
    )
