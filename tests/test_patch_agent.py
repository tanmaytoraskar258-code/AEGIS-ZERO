from types import SimpleNamespace

import pytest
import requests

from src.synthesizer.patch_agent import PatchAgent


@pytest.mark.parametrize(
    ("api_key", "expected_url"),
    [
        (
            "AIza-test-key",
            "https://generativelanguage.googleapis.com/v1beta/models/"
            "gemini-2.5-flash:generateContent?key=AIza-test-key",
        ),
        (
            "AQ.test-key",
            "https://aiplatform.googleapis.com/v1/publishers/google/models/"
            "gemini-2.5-flash:generateContent?key=AQ.test-key",
        ),
    ],
)
def test_generate_patch_uses_endpoint_for_key_type(monkeypatch, api_key, expected_url):
    monkeypatch.setenv("GEMINI_API_KEY", api_key)
    agent = PatchAgent(
        {
            "synthesizer": {
                "model": "gemini-2.5-flash",
                "temperature": 0.1,
                "max_tokens": 128,
            }
        }
    )
    vuln = SimpleNamespace(
        finding=SimpleNamespace(
            cwe_ids=["CWE-502"],
            cve_id="CVE-2020-0001",
            summary="unsafe parsing",
        ),
        call_path=["app.py::main", "EXTERNAL::yaml.load"],
        target_file="app.py",
    )
    response = SimpleNamespace(
        raise_for_status=lambda: None,
        json=lambda: {
            "candidates": [
                {"content": {"parts": [{"text": "--- a/app.py\n+++ b/app.py\n"}]}}
            ]
        },
    )
    requested_urls = []

    def requests_post(url, **kwargs):
        requested_urls.append(url)
        return response

    monkeypatch.setattr("src.synthesizer.patch_agent.requests.post", requests_post)

    agent.generate_patch(vuln, "code")

    assert requested_urls == [expected_url]


def test_generate_patch_rejects_unknown_key_format(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "not-a-supported-key")
    agent = PatchAgent(
        {
            "synthesizer": {
                "model": "gemini-2.5-flash",
                "temperature": 0.1,
                "max_tokens": 128,
            }
        }
    )

    vuln = SimpleNamespace(
        finding=SimpleNamespace(cwe_ids=[], cve_id="CVE-2020-0001", summary=""),
        call_path=[],
        target_file="app.py",
    )

    with pytest.raises(ValueError, match="unsupported format"):
        agent.generate_patch(vuln, "code")


def test_pipeline_records_patch_generation_failures_and_continues():
    from src.ingestion.cve_matcher import VulnerabilityFinding
    from src.pipeline import RemediationPipeline
    from src.reachability.path_pruner import ReachableVulnerability

    findings = [
        ReachableVulnerability(
            finding=VulnerabilityFinding(
                cve_id=f"CVE-2020-000{i}",
                cwe_ids=[],
                package_name="package",
                package_version="1.0",
                ecosystem="PyPI",
                summary="test",
            ),
            call_path=["app.py::main"],
            target_file="app.py",
            sink_function="package.call",
        )
        for i in range(1, 3)
    ]
    pipeline = RemediationPipeline.__new__(RemediationPipeline)
    pipeline.docker_runner = SimpleNamespace(build_sandbox_images=lambda: None)
    pipeline.sbom_parser = SimpleNamespace(parse_repository=lambda _repo: [])
    pipeline.cve_matcher = SimpleNamespace(scan_dependencies=lambda *_args, **_kwargs: [])
    pipeline.ast_extractor = SimpleNamespace(extract_from_repo=lambda _repo: [])
    pipeline.cg_builder = SimpleNamespace(build_graph=lambda _nodes: object())
    pipeline.path_pruner = SimpleNamespace(
        prune_unreachable=lambda _graph, _findings: findings
    )
    pipeline.context_slicer = SimpleNamespace(
        extract_context=lambda *_args: "test context"
    )

    def generate_patch(_vuln, _context):
        raise requests.HTTPError("API request failed")

    pipeline.patch_agent = SimpleNamespace(generate_patch=generate_patch)
    pipeline.patch_applier = SimpleNamespace()
    pipeline.exploit_verifier = SimpleNamespace()
    pipeline.regression_runner = SimpleNamespace()
    pipeline.max_retries = 2

    result = pipeline.run("repo", build_images=False)

    assert [outcome.cve_id for outcome in result.outcomes] == [
        "CVE-2020-0001",
        "CVE-2020-0002",
    ]
    assert all(not outcome.patched_successfully for outcome in result.outcomes)
    assert all(outcome.attempts_used == 2 for outcome in result.outcomes)
    assert all(
        outcome.status_message == "Patch generation failed: API request failed"
        for outcome in result.outcomes
    )
