import os
import tempfile
from src.ingestion.cve_matcher import VulnerabilityFinding
from src.reachability import ASTExtractor, CallGraphBuilder, PathPruner


def test_reachability_prunes_false_positives():
    """Verifies that reachable CVEs are retained while unreachable CVEs are pruned."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create a sample app that uses yaml.load() (reachable)
        # Note: 'requests' is NOT imported or called anywhere (unreachable false positive)
        app_code = (
            "import yaml\n\n"
            "def parse_config(raw_data):\n"
            "    return yaml.load(raw_data, Loader=yaml.Loader)\n\n"
            "def main():\n"
            "    data = 'user: admin'\n"
            "    return parse_config(data)\n"
        )
        app_path = os.path.join(tmp_dir, "app.py")
        with open(app_path, "w", encoding="utf-8") as f:
            f.write(app_code)

        # Extract AST & build graph
        extractor = ASTExtractor()
        nodes = extractor.extract_from_repo(tmp_dir)
        graph = CallGraphBuilder().build_graph(nodes)

        # Simulate two CVEs reported by baseline scanner:
        # 1. CVE-2020-14343 in PyYAML (Reachable via main -> parse_config -> yaml.load)
        # 2. CVE-2023-32681 in requests (Unreachable - dead dependency)
        findings = [
            VulnerabilityFinding(
                cve_id="CVE-2020-14343",
                cwe_ids=["CWE-502"],
                package_name="PyYAML",
                package_version="5.3.1",
                ecosystem="PyPI",
                summary="Arbitrary code execution via unsafe yaml.load()",
                affected_functions=["yaml.load"],
            ),
            VulnerabilityFinding(
                cve_id="CVE-2023-32681",
                cwe_ids=["CWE-200"],
                package_name="requests",
                package_version="2.28.0",
                ecosystem="PyPI",
                summary="Unintended leak of Proxy-Authorization header",
                affected_functions=["requests.Session.send"],
            ),
        ]

        pruner = PathPruner(max_depth=10)
        reachable = pruner.prune_unreachable(graph, findings)

        assert len(reachable) == 1
        assert reachable[0].finding.cve_id == "CVE-2020-14343"
        assert reachable[0].target_file == "app.py"
        assert "EXTERNAL::yaml.load" in reachable[0].call_path[-1]
